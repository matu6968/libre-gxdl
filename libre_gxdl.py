#!/usr/bin/env python3
"""
libre-gxdl: Open Source GX Bootloader Tool
Reverse engineered from gxdl.elf via hardware sniffing and binary analysis

Supports GX/Nationalchip set-top boxes running eCos 3.x RTOS:
- Gemini (GX6701, GX6702, GX6703)
- Cygnus (GX6705, GX6706)
- Sirius (GX6613)
- Taurus (GX3113, GX3235, GX6605)
- And more...
Keep in mind that support is untested for other devices (only tested on GX6702) and may not work, so try at your own risk.

Features:
- Boot device via serial
- Read/write flash via serial or USB
- OTP memory operations (GX OTP, SPI Flash OTP)
- Flash management (erase, bad block info)
- File comparison

Protocol Summary:
================
1. Device sends handshake: B0 B0 58 (ACK sequence)
2. Host sends Stage 1:
   - 5-byte header: [0x59][len_lo][len_hi][addr_lo][addr_hi]
   - 8188 bytes payload from boot file offset 0x20 (includes checksum)
   - "boot" terminator
3. Device responds: "RUNGET"
4. Host sends Stage 2:
   - 8-byte metadata: checksum16 + 0x00C2 + size32
   - Boot content in 2048-byte chunks
5. Device boots and shows partition info

Usage:
  python3 libre_gxdl.py -b <bootfile> -d <serial_device> [-c <command>] [-v]
"""

import argparse
import binascii
import serial
import struct
import sys
import time
import termios
import os


class GXUploader:
    def __init__(self, device: str, baudrate: int = 115200, verbose: bool = False):
        self.verbose = verbose
        self.device = device
        self.baudrate = baudrate
        self.ser = None
        self.reset_dtr = False
        self.reset_rts = False

    def log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def open(self):
        """Open serial port with exact settings matching vendor strace"""
        self.ser = serial.Serial(
            port=self.device,
            baudrate=self.baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.1,
            xonxoff=False,    # No software flow control
            rtscts=False,     # No hardware flow control
            dsrdtr=False,     # No DSR/DTR flow control
            write_timeout=5.0,
            inter_byte_timeout=None
        )
        
        # Apply vendor-exact termios settings (from strace ioctl analysis)
        # Key: INPCK flag and raw mode as vendor uses
        fd = self.ser.fileno()
        attrs = termios.tcgetattr(fd)
        
        # c_iflag: INPCK only (input parity checking)
        attrs[0] = termios.INPCK
        # c_oflag: 0 (no output processing)
        attrs[1] = 0
        # c_cflag: keep existing (CS8|CREAD|HUPCL|CLOCAL|B115200)
        # c_lflag: 0 (raw mode)
        attrs[3] = 0
        
        # Apply settings
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        
        # Do TCSBRK (drain) and TCFLSH (flush) like vendor
        termios.tcdrain(fd)
        termios.tcflush(fd, termios.TCIOFLUSH)
        
        # Set RTS and DTR low initially
        self.ser.rts = False
        self.ser.dtr = False
        time.sleep(0.05)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        self.log(f"Opened {self.device} at {self.baudrate} baud (vendor termios settings)")

    def close(self):
        """Close serial port"""
        if self.ser:
            self.ser.close()
            self.ser = None

    def flush_and_wait(self, settle_ms: int = 100):
        """Flush serial buffers and wait for line to settle"""
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        time.sleep(settle_ms / 1000.0)
        # Drain any remaining bytes
        while self.ser.in_waiting:
            self.ser.read(self.ser.in_waiting)
            time.sleep(0.01)

    def pulse_reset(self):
        """Pulse DTR/RTS lines to reset the device"""
        if not (self.reset_dtr or self.reset_rts):
            return
        
        self.log("Pulsing reset lines...")
        
        if self.reset_dtr:
            self.ser.dtr = True
            time.sleep(0.1)
            self.ser.dtr = False
            self.log("  DTR pulsed")
        
        if self.reset_rts:
            self.ser.rts = True
            time.sleep(0.1)
            self.ser.rts = False
            self.log("  RTS pulsed")
        
        # Wait for device to reset
        time.sleep(0.2)
        self.flush_and_wait(50)

    def wait_for_handshake(self, timeout: float = 30.0) -> bool:
        """
        Wait for device handshake sequence.
        
        Known handshake patterns (all end with 0x58):
        - B0 B0 58 (3 bytes) - from sniffed data  
        - B8 B0 FF 58 (4 bytes) - alternate
        - B0 30 FF 58 (4 bytes) - seen in some logs
        
        Detection: Look for 0x58 preceded by B0 or B8 prefix bytes
        
        IMPORTANT: Must respond IMMEDIATELY after handshake!
        """
        self.log("Waiting for device handshake...")
        self.log("Power cycle the device or press reset NOW!")
        
        # Flush any stale data first  
        self.flush_and_wait(50)
        
        buffer = bytearray()
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Read all available data at once for speed
            waiting = self.ser.in_waiting
            if waiting > 0:
                data = self.ser.read(waiting)
                buffer.extend(data)
                
                if self.verbose:
                    for b in data:
                        ch = chr(b) if 32 <= b < 127 else '.'
                        print(f"    Rx: 0x{b:02X} '{ch}'")
                
                # Check for handshake terminator (0x58) with proper prefix
                for i in range(len(buffer)):
                    if buffer[i] == 0x58 and i >= 2:
                        # Check if this looks like a handshake
                        start_idx = max(0, i - 3)
                        candidate = buffer[start_idx:i+1]
                        
                        # Valid if starts with B0 or B8
                        if candidate[0] in (0xB0, 0xB8):
                            self.log(f"Handshake detected: {candidate.hex()}")
                            # Clear any remaining buffered data
                            time.sleep(0.005)
                            if self.ser.in_waiting:
                                self.ser.read(self.ser.in_waiting)
                            return True
                
                # Keep buffer small - only need last few bytes
                if len(buffer) > 32:
                    buffer = buffer[-32:]
            else:
                # No data - short sleep
                time.sleep(0.001)
        
        print("[!] Timeout waiting for handshake")
        if buffer:
            print(f"    Last bytes: {buffer.hex()}")
        return False

    def send_stage1(self, boot_data: bytes) -> bool:
        """
        Send Stage 1: Initial bootloader chunk
        
        Format:
        - Header (5 bytes): [0x59][len_lo][len_hi][addr_lo][addr_hi]
        - Payload (8184 bytes): boot_data[0x20:0x2018]
        - Checksum (4 bytes): boot_data[0x2018:0x201C] (embedded in file)
        
        The length field is (payload_size >> 2) in little-endian, meaning
        0x0800 = 2048 words = 8192 bytes (but we send 8184 + 4 checksum = 8188)
        
        IMPORTANT: Must send quickly after handshake - device has short timeout!
        """
        self.log("Sending Stage 1 (must be fast!)...")
        
        # Extract payload and embedded checksum from boot file
        payload_start = 0x20
        payload_end = 0x2018
        checksum_end = 0x201C
        
        payload = boot_data[payload_start:payload_end]
        checksum = boot_data[payload_end:checksum_end]
        
        # Build header: 0x59 followed by length (in 4-byte words) and address
        # Length field: 0x0800 = 2048 words = 8192 bytes
        length_field = 0x0800  # This seems to be fixed
        addr_field = 0x0000    # First block
        
        header = bytes([
            0x59,
            length_field & 0xFF,
            (length_field >> 8) & 0xFF,
            addr_field & 0xFF,
            (addr_field >> 8) & 0xFF,
        ])
        
        # Build complete packet and send in ONE write for speed
        packet = header + payload + checksum
        
        # Send entire packet at once
        bytes_written = self.ser.write(packet)
        self.ser.flush()
        
        self.log(f"  Header: {header.hex()}")
        self.log(f"  Payload: {len(payload)} bytes from boot[0x{payload_start:X}:0x{payload_end:X}]")
        self.log(f"  Checksum: {checksum.hex()} (embedded in boot file)")
        self.log(f"  Total Stage 1: {bytes_written} bytes sent")
        
        return bytes_written == len(packet)

    def wait_for_run_get(self, timeout: float = 15.0) -> bool:
        """
        Wait for 'RUN' and 'GET' responses from device.
        The device sends "RUNGET" (6 bytes) or "RUN" then "GET" separately.
        
        From sniffed data:
        - recv_000002.txt: "RUNGET" (52 55 4E 47 45 54)
        
        Vendor timing: ~736ms after Stage 1 complete
        """
        self.log("Waiting for RUNGET response (up to 15s)...")
        
        buffer = bytearray()
        start_time = time.time()
        got_run = False
        got_get = False
        last_rx_time = start_time
        
        while time.time() - start_time < timeout:
            # Read all available data
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
                last_rx_time = time.time()
                
                if self.verbose:
                    for b in data:
                        ch = chr(b) if 32 <= b < 127 else '.'
                        print(f"    Rx: 0x{b:02X} '{ch}'")
                
                # Check for RUN
                if b"RUN" in buffer and not got_run:
                    print("[*] Received RUN")
                    got_run = True
                
                # Check for GET
                if b"GET" in buffer and not got_get:
                    print("[*] Received GET")
                    got_get = True
                
                # If we have both, we're done
                if got_run and got_get:
                    return True
                
                # Also accept just "RUN" followed by silence (some devices)
                if got_run and (time.time() - last_rx_time) > 1.0:
                    print("[*] Got RUN, proceeding without explicit GET")
                    return True
            else:
                time.sleep(0.005)
        
        # Print what we got for debugging
        elapsed = time.time() - start_time
        if buffer:
            try:
                text = buffer.decode('latin-1')
                print(f"[!] Timeout after {elapsed:.1f}s waiting for RUNGET")
                print(f"[!] Got {len(buffer)} bytes: {repr(text[:100])}")
            except:
                print(f"[!] Timeout after {elapsed:.1f}s. Got: {buffer[:100].hex()}")
        else:
            print(f"[!] Timeout after {elapsed:.1f}s - no data received from device")
            print("[!] Possible causes:")
            print("    - Stage 1 data was corrupted in transmission")
            print("    - Device is in wrong state (try power cycle)")
            print("    - Serial TX line issue (check wiring)")
        
        return False

    def send_stage2(self, boot_data: bytes) -> bool:
        """
        Send Stage 2 based on strace of vendor tool:
        
        Metadata (8 bytes in two 4-byte writes):
        - Part 1: checksum16 (2B LE) + field2 (2B LE) = 0x00C2
        - Part 2: boot_size (4B LE)
        
        Payload: Full boot file content in 2048-byte chunks
        - Starts with "toob" magic
        - Then code from boot[0x20:]
        """
        self.log("Sending Stage 2...")
        
        boot_size = len(boot_data)
        
        # Build boot content: "toob" + code (skip header bytes 4-31)
        boot_content = boot_data[0:4] + boot_data[0x20:]  # "toob" + code
        
        # Pad to original size with zeros if needed
        if len(boot_content) < boot_size:
            boot_content += bytes(boot_size - len(boot_content))
        
        # Calculate 16-bit checksum of boot content
        checksum16 = sum(boot_content) & 0xFFFF
        self.log(f"  Boot content checksum: 0x{checksum16:04X}")
        
        # Build metadata parts (NO "boot" magic - that was sent in Stage 1!)
        # Part 1: checksum16 + field2 (0x00C2)
        meta_part1 = struct.pack("<H", checksum16) + struct.pack("<H", 0x00C2)
        # Part 2: boot_size
        meta_part2 = struct.pack("<I", boot_size)
        
        self.log(f"  Metadata part 1: {meta_part1.hex()}")
        self.log(f"  Metadata part 2: {meta_part2.hex()}")
        
        # Send metadata as two separate 4-byte writes (like vendor)
        self.ser.write(meta_part1)
        self.ser.write(meta_part2)
        
        # Send boot content in 2048-byte chunks (like vendor)
        chunk_size = 2048
        sent = 0
        
        while sent < len(boot_content):
            chunk = boot_content[sent:sent + chunk_size]
            self.ser.write(chunk)
            sent += len(chunk)
            
            # Progress
            pct = (sent * 100) // len(boot_content)
            print(f"\r  Progress: {pct}%", end="", flush=True)
        
        print()
        self.ser.flush()
        
        total = len(meta_part1) + len(meta_part2) + len(boot_content)
        self.log(f"  Total Stage 2: {total} bytes")
        return True

    def read_response(self, timeout: float = 10.0):
        """Read and print device response after boot"""
        self.log("Reading device response...")
        
        start_time = time.time()
        buffer = bytearray()
        
        while time.time() - start_time < timeout:
            data = self.ser.read(256)
            if data:
                buffer.extend(data)
                # Try to decode and print
                try:
                    text = data.decode('latin-1')
                    print(text, end="", flush=True)
                except:
                    print(data.hex(), end=" ", flush=True)
            else:
                # If we have data and silence, might be done
                if len(buffer) > 100:
                    time.sleep(0.5)
                    if not self.ser.in_waiting:
                        break
                time.sleep(0.01)
        
        print()
        return buffer

    def upload(self, boot_file: str) -> bool:
        """Main upload sequence"""
        # Load boot file
        with open(boot_file, "rb") as f:
            boot_data = f.read()
        
        # Validate boot file
        if len(boot_data) < 0x2020:
            print(f"[!] Boot file too small: {len(boot_data)} bytes")
            return False
        
        if boot_data[0:4] != b"toob":
            print(f"[!] Invalid boot file magic: {boot_data[0:4].hex()}")
            return False
        
        print(f"[+] Loaded boot file: {boot_file} ({len(boot_data)} bytes)")
        
        # Parse boot header
        version = struct.unpack("<H", boot_data[4:6])[0]
        chip = struct.unpack("<H", boot_data[6:8])[0]
        baud = struct.unpack("<I", boot_data[8:12])[0]
        print(f"    Version: 0x{version:04X}, Chip: 0x{chip:04X}, Baud: {baud}")
        
        # Pre-build Stage 1 parts based on strace analysis
        header, payload, terminator = self._build_stage1_parts(boot_data)
        
        try:
            self.open()
            
            # Step 0: Reset device if requested
            self.pulse_reset()
            
            # Step 1: Wait for handshake
            if not self.wait_for_handshake():
                return False
            
            # Step 2: Send Stage 1 (matching vendor strace exactly!)
            # Vendor sends: header(5) + payload(8188) + "boot"(4) = 8197 bytes
            self.log("Sending Stage 1...")
            
            # Flush buffers before sending (like vendor does)
            fd = self.ser.fileno()
            termios.tcflush(fd, termios.TCIOFLUSH)
            
            # Send header (5 bytes)
            self.ser.write(header)
            self.log(f"  Header: {header.hex()}")
            
            # Send payload (8188 bytes) - same write as vendor
            self.ser.write(payload)
            self.log(f"  Payload: {len(payload)} bytes")
            
            # Send "boot" terminator (4 bytes)
            self.ser.write(terminator)
            self.log(f"  Terminator: {terminator}")
            
            # Drain output buffer to ensure physical transmission (like vendor)
            termios.tcdrain(fd)
            
            total_sent = len(header) + len(payload) + len(terminator)
            self.log(f"  Total Stage 1: {total_sent} bytes")
            
            # Step 3: Wait for RUNGET
            if not self.wait_for_run_get(timeout=10.0):
                print("[!] Failed to get RUNGET response")
                print("[!] Device may have timed out - try again with faster reset")
                return False
            
            # Step 4: Small delay then send Stage 2
            time.sleep(0.05)  # 50ms
            if not self.send_stage2(boot_data):
                return False
            
            # Step 5: Read response
            print("\n[+] Boot sequence complete, reading device output:")
            print("-" * 60)
            self.read_response(timeout=15.0)
            print("-" * 60)
            
            print("\n[+] Upload successful!")
            return True
            
        except serial.SerialException as e:
            print(f"[!] Serial error: {e}")
            return False
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            return False
        finally:
            self.close()
    
    def _build_stage1_parts(self, boot_data: bytes) -> tuple:
        """
        Build Stage 1 parts based on strace of vendor tool:
        1. Header (5 bytes): 59 00 08 00 00
        2. Payload (8188 bytes): boot_data[0x20:0x201C] - includes checksum!
        3. "boot" terminator (4 bytes)
        """
        header = bytes([0x59, 0x00, 0x08, 0x00, 0x00])
        payload = boot_data[0x20:0x201C]  # 8188 bytes (includes checksum)
        terminator = b"boot"
        
        return header, payload, terminator

    def wait_for_prompt(self, timeout: float = 5.0) -> bool:
        """
        Wait for 'boot>' prompt. If nothing arrives shortly, send a newline to
        coax the prompt to reappear (helps when the previous prompt was already
        consumed).
        """
        buffer = bytearray()
        start = time.time()
        poked = False
        fd = self.ser.fileno()
        
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
                if b"boot> " in buffer or b"boot>" in buffer:
                    return True
            else:
                # If no data yet, send a newline once to trigger prompt output
                if not poked and time.time() - start > 0.2:
                    try:
                        self.ser.write(b"\n")
                        termios.tcdrain(fd)
                    except Exception:
                        pass
                    poked = True
                time.sleep(0.01)
        
        return False

    def send_command(self, command: str, timeout: float = 5.0) -> tuple:
        """
        Send a command to bootloader and wait for echo.
        
        Returns:
            (success, extra_data) - success bool and any data read after echo
        """
        self.log(f"Sending command: {command}")
        
        # Send command with newline
        self.ser.write(command.encode() + b"\n")
        termios.tcdrain(self.ser.fileno())
        
        # Wait for echo and capture any extra data
        buffer = bytearray()
        start = time.time()
        
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
                # Check if we got the command echoed back (plus newline)
                cmd_bytes = command.encode()
                if cmd_bytes in buffer:
                    # Find where the echo ends (after \r\n)
                    idx = buffer.find(cmd_bytes) + len(cmd_bytes)
                    # Skip past any trailing \r\n
                    while idx < len(buffer) and buffer[idx:idx+1] in (b'\r', b'\n'):
                        idx += 1
                    # Return any extra data after the echo
                    extra = bytes(buffer[idx:])
                    return (True, extra)
            time.sleep(0.01)
        
        return (False, b"")

    def serial_dump(self, target: str, size: int, output_file: str) -> bool:
        """
        Dump flash contents via serial.
        
        Protocol:
        1. Send: serialdump <partition|addr> <size>
        2. Wait for ~sta~ marker
        3. Read raw binary data (1024-byte chunks)
        4. Wait for ~crc~ + 4-byte CRC
        5. Wait for ~fin~ marker
        
        Args:
            target: Partition name (e.g., "BOOT") or flash address (e.g., "0x0")
            size: Number of bytes to dump
            output_file: Output file path
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        # Wait for prompt first
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        # Send serialdump command (without filename - that's for the host)
        command = f"serialdump {target} {size}"
        success, extra = self.send_command(command, timeout=5.0)
        if not success:
            print("[!] Command not echoed back")
            return False
        
        print(f"[*] Dumping {size} bytes from {target}...")
        
        # Start with any extra data from command echo
        buffer = bytearray(extra)
        
        # Wait for ~sta~ marker
        start = time.time()
        
        while time.time() - start < 10.0:
            if b"~sta~" in buffer:
                idx = buffer.find(b"~sta~")
                buffer = buffer[idx + 5:]
                break
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
            time.sleep(0.01)
        else:
            print("[!] Timeout waiting for ~sta~ marker")
            return False
        
        self.log("Got ~sta~ marker, receiving data...")
        
        # Read binary data
        data_buffer = buffer  # May already have some data after ~sta~
        bytes_received = len(data_buffer)
        last_progress = 0
        last_data_time = time.time()
        
        # Calculate timeout based on size (~10KB/s expected, with 30s margin)
        expected_time = size / 10000  # seconds at 10KB/s
        total_timeout = max(120, expected_time + 60)  # at least 2 minutes
        
        print(f"[*] Expected transfer time: ~{int(expected_time)}s")
        
        start = time.time()
        
        while bytes_received < size:
            if self.ser.in_waiting:
                chunk = self.ser.read(min(4096, self.ser.in_waiting))
                data_buffer.extend(chunk)
                bytes_received = len(data_buffer)
                last_data_time = time.time()
                
                # Progress update
                progress = int(bytes_received * 100 / size)
                if progress != last_progress and progress % 5 == 0:
                    elapsed = time.time() - start
                    speed = bytes_received / elapsed if elapsed > 0 else 0
                    remaining = (size - bytes_received) / speed if speed > 0 else 0
                    print(f"  Progress: {progress}% ({speed/1024:.1f} KB/s, ~{int(remaining)}s remaining)", end="    \r")
                    last_progress = progress
            else:
                # Check for data timeout (no data for 30 seconds)
                if time.time() - last_data_time > 30.0:
                    print(f"\n[!] No data received for 30s at {bytes_received}/{size} bytes")
                    return False
                # Check for total timeout
                if time.time() - start > total_timeout:
                    print(f"\n[!] Total timeout after receiving {bytes_received}/{size} bytes")
                    return False
                time.sleep(0.001)
        
        print(f"  Progress: 100%")
        
        # Wait for ~crc~ marker
        extra_data = bytearray()
        start = time.time()
        
        while time.time() - start < 5.0:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                extra_data.extend(data)
                if b"~crc~" in extra_data:
                    idx = extra_data.find(b"~crc~")
                    # Read 4-byte CRC after marker
                    crc_start = idx + 5
                    if len(extra_data) >= crc_start + 4:
                        crc_bytes = extra_data[crc_start:crc_start + 4]
                        crc_value = struct.unpack("<I", crc_bytes)[0]
                        self.log(f"Device CRC: 0x{crc_value:08X}")
                        break
            time.sleep(0.01)
        else:
            print("[!] Warning: ~crc~ marker not found")
        
        # Wait for ~fin~ marker
        start = time.time()
        while time.time() - start < 2.0:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                extra_data.extend(data)
                if b"~fin~" in extra_data:
                    self.log("Got ~fin~ marker")
                    break
            time.sleep(0.01)
        
        # Extract exactly the requested size
        dump_data = bytes(data_buffer[:size])
        
        # Write to file
        with open(output_file, "wb") as f:
            f.write(dump_data)
        
        print(f"[+] Wrote {len(dump_data)} bytes to {output_file}")
        return True

    def serial_download(self, target: str, input_file: str) -> bool:
        """
        Download (write) data to flash via serial.
        
        Protocol:
        1. Send: serialdown <partition|addr> <size>
        2. Wait for device ready
        3. Send data in chunks
        4. Wait for completion
        
        Args:
            target: Partition name (e.g., "BOOT") or flash address (e.g., "0x0")
            input_file: Input file path to flash
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        # Read input file
        with open(input_file, "rb") as f:
            data = f.read()
        
        size = len(data)
        print(f"[*] Downloading {size} bytes to {target}...")
        
        # Wait for prompt first
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        # Send serialdown command
        command = f"serialdown {target} {size}"
        success, extra = self.send_command(command, timeout=5.0)
        if not success:
            print("[!] Command not echoed back")
            return False
        
        # Wait for device ready marker ~sta~
        buffer = bytearray(extra)
        start = time.time()
        
        while time.time() - start < 10.0:
            if b"~sta~" in buffer:
                break
            if self.ser.in_waiting:
                recv = self.ser.read(self.ser.in_waiting)
                buffer.extend(recv)
            time.sleep(0.01)
        else:
            print("[!] Timeout waiting for device ready")
            return False
        
        self.log("Device ready, sending data...")
        
        # Send data in 1024-byte chunks
        chunk_size = 1024
        bytes_sent = 0
        
        # GX custom checksum: sum of (key[i%4] ^ data[i]) for all bytes
        # Key = [0x12, 0x34, 0x56, 0x78] (from reverse engineering gxdl.elf)
        GX_KEY = bytes([0x12, 0x34, 0x56, 0x78])
        checksum = 0
        
        while bytes_sent < size:
            chunk = data[bytes_sent:bytes_sent + chunk_size]
            self.ser.write(chunk)
            
            # Update GX checksum
            for i, byte in enumerate(chunk):
                xored = GX_KEY[(bytes_sent + i) % 4] ^ byte
                checksum += xored
            
            bytes_sent += len(chunk)
            
            # Progress update
            progress = int(bytes_sent * 100 / size)
            if progress % 5 == 0:
                print(f"  Progress: {progress}%", end="\r")
        
        termios.tcdrain(self.ser.fileno())
        print(f"  Progress: 100%")
        
        # Wait for ~crc~ marker from device
        buffer = bytearray()
        start = time.time()
        
        print("[*] Waiting for CRC request...")
        while time.time() - start < 10.0:
            if self.ser.in_waiting:
                recv = self.ser.read(self.ser.in_waiting)
                buffer.extend(recv)
                if b"~crc~" in buffer:
                    break
            time.sleep(0.01)
        else:
            print(f"[!] Timeout waiting for ~crc~ marker. Got: {buffer}")
            return False
        
        # Send GX checksum (4 bytes, big-endian)
        # This is the custom GX checksum, NOT standard CRC32!
        checksum_final = checksum & 0xFFFFFFFF
        checksum_bytes = struct.pack(">I", checksum_final)  # Big-endian
        self.ser.write(checksum_bytes)
        termios.tcdrain(self.ser.fileno())
        self.log(f"Sent checksum: 0x{checksum_final:08X} (bytes: {checksum_bytes.hex()})")
        
        # Wait for completion - device will show ~fin~, then erase, write, and possibly reboot
        buffer = bytearray()
        start = time.time()
        timeout = 120.0  # Flash erase/write can take a while
        
        print("[*] Waiting for flash erase and write...")
        
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                recv = self.ser.read(self.ser.in_waiting)
                buffer.extend(recv)
                
                # Check for various completion markers
                buffer_str = buffer.decode('latin-1', errors='replace')
                
                # Success indicators
                if b"~fin~" in buffer:
                    self.log("Got ~fin~ marker")
                
                # Check for checksum error
                if b"err:" in buffer and b"crc" in buffer.lower():
                    print(f"\n[!] Checksum verification failed:")
                    print(f"    {buffer_str.strip()}")
                    return False
                
                # Device shows partition table after successful write
                if b"Partition Version" in buffer:
                    if self.verbose:
                        print(f"\n{buffer_str}")
                    print("[+] Download complete - flash written successfully!")
                    return True
                
                # Also check for boot prompt (might appear without partition table)
                if b"boot>" in buffer and (b"~fin~" in buffer or b"Erase" in buffer):
                    if self.verbose:
                        print(f"\n{buffer_str}")
                    print("[+] Download complete!")
                    return True
                    
            time.sleep(0.01)
        
        # Timeout - show what we received
        print(f"\n[!] Timeout waiting for completion. Received:")
        print(buffer.decode('latin-1', errors='replace')[-500:])
        return False

    def text_command(self, command: str, timeout: float = 5.0) -> str:
        """
        Send a text command and capture the text response.
        
        Args:
            command: Command string to send
            timeout: Response timeout
        
        Returns:
            Response text (or empty string on failure)
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return ""
        
        # Wait for prompt first
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return ""
        
        # Send command
        self.log(f"Sending text command: {command}")
        self.ser.write(command.encode() + b"\n")
        termios.tcdrain(self.ser.fileno())
        
        # Read response until we see boot> prompt again
        buffer = bytearray()
        start = time.time()
        
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
                # Check if we're back at boot prompt
                if b"boot>" in buffer:
                    break
            time.sleep(0.01)
        
        # Extract the response (skip command echo, stop at boot>)
        response = buffer.decode('latin-1', errors='replace')
        
        # Find the actual response (after command echo, before boot>)
        lines = response.split('\n')
        result_lines = []
        found_command = False
        for line in lines:
            if command in line:
                found_command = True
                continue
            if 'boot>' in line:
                break
            if found_command:
                result_lines.append(line.strip())
        
        return '\n'.join(result_lines).strip()

    def binary_read_command(self, command: str, size: int, output_file: str) -> bool:
        """
        Generic binary read command using ~sta~/~crc~/~fin~ protocol.
        Used for: gx_otp read, sflash_otp read, serialdump
        
        Args:
            command: Full command string (e.g., "gx_otp read 0 32")
            size: Expected data size in bytes
            output_file: Output file path
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        # Wait for prompt first
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        # Send command (may include extra data after echo)
        success, extra = self.send_command(command, timeout=5.0)
        if not success:
            print("[!] Command not echoed back")
            return False
        
        print(f"[*] Reading {size} bytes...")
        
        # Start with any extra data from command echo
        buffer = bytearray(extra)
        
        # Wait for ~sta~ marker
        start = time.time()
        
        while time.time() - start < 10.0:
            if b"~sta~" in buffer:
                idx = buffer.find(b"~sta~")
                buffer = buffer[idx + 5:]
                break
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
            time.sleep(0.01)
        else:
            print("[!] Timeout waiting for ~sta~ marker")
            self.log(f"Buffer contents: {buffer[:100]}")
            return False
        
        self.log("Got ~sta~ marker, receiving data...")
        
        # Read binary data
        data_buffer = buffer
        bytes_received = len(data_buffer)
        last_progress = 0
        last_data_time = time.time()
        
        # Short timeout for small reads
        total_timeout = max(30, size / 5000 + 10)
        
        while bytes_received < size:
            if self.ser.in_waiting:
                chunk = self.ser.read(min(4096, self.ser.in_waiting))
                data_buffer.extend(chunk)
                bytes_received = len(data_buffer)
                last_data_time = time.time()
                
                # Progress update for larger transfers
                if size > 1024:
                    progress = int(bytes_received * 100 / size)
                    if progress != last_progress and progress % 10 == 0:
                        print(f"  Progress: {progress}%", end="\r")
                        last_progress = progress
            else:
                if time.time() - last_data_time > 15.0:
                    print(f"\n[!] No data received for 15s at {bytes_received}/{size} bytes")
                    return False
                if time.time() - start > total_timeout:
                    print(f"\n[!] Timeout after receiving {bytes_received}/{size} bytes")
                    return False
                time.sleep(0.001)
        
        if size > 1024:
            print(f"  Progress: 100%")
        
        # Wait for ~crc~ and ~fin~ markers
        extra_data = bytearray()
        start = time.time()
        while time.time() - start < 5.0:
            if self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)
                extra_data.extend(data)
                if b"~fin~" in extra_data or b"boot>" in extra_data:
                    break
            time.sleep(0.01)
        
        # Extract data
        dump_data = bytes(data_buffer[:size])
        
        # Write to file
        with open(output_file, "wb") as f:
            f.write(dump_data)
        
        print(f"[+] Wrote {len(dump_data)} bytes to {output_file}")
        return True

    def gx_otp_read(self, address: int, length: int, output_file: str) -> bool:
        """Read GX OTP memory to file."""
        command = f"gx_otp read {address} {length}"
        return self.binary_read_command(command, length, output_file)

    def gx_otp_tread(self, address: int, length: int) -> str:
        """Read GX OTP memory as text (hex dump)."""
        command = f"gx_otp tread {address} {length}"
        return self.text_command(command, timeout=5.0)

    def sflash_otp_status(self) -> str:
        """Get SPI Flash OTP status."""
        return self.text_command("sflash_otp status", timeout=5.0)

    def sflash_otp_getregion(self) -> str:
        """Get SPI Flash OTP region."""
        return self.text_command("sflash_otp getregion", timeout=5.0)

    def sflash_otp_read(self, address: int, length: int, output_file: str) -> bool:
        """Read SPI Flash OTP to file."""
        command = f"sflash_otp read {address} {length}"
        return self.binary_read_command(command, length, output_file)

    def compare_files(self, src_file: str, dst_file: str) -> bool:
        """
        Compare two files byte-by-byte (host-side operation).
        
        This mimics the 'compare' command from gxdl.elf which compares
        local files without device interaction.
        
        Args:
            src_file: Source file path
            dst_file: Destination file path
        
        Returns:
            True if files are identical
        """
        try:
            with open(src_file, "rb") as f1:
                data1 = f1.read()
            with open(dst_file, "rb") as f2:
                data2 = f2.read()
        except FileNotFoundError as e:
            print(f"[!] File not found: {e.filename}")
            return False
        except IOError as e:
            print(f"[!] Error reading file: {e}")
            return False
        
        size1, size2 = len(data1), len(data2)
        
        if size1 != size2:
            print(f"[!] Files differ in size:")
            print(f"    {src_file}: {size1} bytes")
            print(f"    {dst_file}: {size2} bytes")
            return False
        
        # Compare in chunks for progress and to find first difference
        chunk_size = 4 * 1024 * 1024  # 4MB chunks
        offset = 0
        
        while offset < size1:
            end = min(offset + chunk_size, size1)
            chunk1 = data1[offset:end]
            chunk2 = data2[offset:end]
            
            if chunk1 != chunk2:
                # Find exact byte offset of first difference
                for i, (b1, b2) in enumerate(zip(chunk1, chunk2)):
                    if b1 != b2:
                        diff_offset = offset + i
                        print(f"[!] Files differ at offset 0x{diff_offset:X}:")
                        print(f"    {src_file}: 0x{b1:02X}")
                        print(f"    {dst_file}: 0x{b2:02X}")
                        return False
            
            offset = end
            if size1 > chunk_size:
                progress = int(offset * 100 / size1)
                print(f"  Comparing: {progress}%", end="\r")
        
        if size1 > chunk_size:
            print(f"  Comparing: 100%")
        
        print(f"[+] Files are identical ({size1} bytes)")
        return True

    def usb_dump(self, target: str, size: int, filename: str) -> bool:
        """
        Dump flash contents via USB (device reads to USB drive).
        
        The bootloader reads flash and writes to a file on USB storage
        connected to the device.
        
        Args:
            target: Partition name or flash address
            size: Number of bytes to dump
            filename: Filename on USB drive (device-side)
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        command = f"usbdump {target} {size} {filename}"
        print(f"[*] USB dump: {target} ({size} bytes) -> {filename}")
        
        result = self.text_command(command, timeout=120.0)
        
        if result:
            print(f"[+] USB dump output:\n{result}")
            # Check for success indicators
            if "ok" in result.lower() or "finish" in result.lower():
                return True
        
        return True  # Command sent, result shown

    def usb_download(self, target: str, filename: str) -> bool:
        """
        Download (write) to flash via USB (device reads from USB drive).
        
        The bootloader reads a file from USB storage connected to the device
        and writes it to flash.
        
        Args:
            target: Partition name or flash address
            filename: Filename on USB drive (device-side)
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        command = f"usbdown {target} {filename}"
        print(f"[*] USB download: {filename} -> {target}")
        print("[!] WARNING: This will ERASE and WRITE flash!")
        
        result = self.text_command(command, timeout=300.0)  # Flash write takes time
        
        if result:
            print(f"[+] USB download output:\n{result}")
            if "ok" in result.lower() or "finish" in result.lower():
                return True
        
        return True  # Command sent, result shown

    def flash_erase(self, target: str, length: int = None, nospread: bool = False) -> bool:
        """
        Erase flash region.
        
        Args:
            target: Partition name or flash address
            length: Length to erase (required if target is address)
            nospread: If True, don't spread erase across bad blocks
        
        Returns:
            True if successful
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        if length is not None:
            if nospread:
                command = f"flash erase nospread {target} {length}"
            else:
                command = f"flash erase {target} {length}"
        else:
            command = f"flash erase {target}"
        
        print(f"[*] Flash erase: {command}")
        print("[!] WARNING: This will ERASE flash data!")
        
        result = self.text_command(command, timeout=120.0)
        
        if result:
            print(f"[+] Flash erase output:\n{result}")
        
        return True

    def flash_badinfo(self) -> bool:
        """Show flash bad block information."""
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        result = self.text_command("flash badinfo", timeout=10.0)
        
        if result:
            print(f"[+] Flash bad block info:\n{result}")
            return True
        
        return False

    def flash_eraseall(self) -> bool:
        """
        Erase entire flash.
        
        WARNING: This is EXTREMELY DANGEROUS and will brick the device
        if not followed by immediate reflash!
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False
        
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False
        
        print("[!] WARNING: flash eraseall will ERASE ALL FLASH DATA!")
        print("[!] This WILL BRICK the device if not immediately reflashed!")
        
        result = self.text_command("flash eraseall", timeout=300.0)
        
        if result:
            print(f"[+] Flash eraseall output:\n{result}")
        
        return True

    def run_command_mode(self, boot_file: str, command: str, cmd_args: list) -> bool:
        """
        Boot device and run a command.
        
        Args:
            boot_file: Boot file to upload first
            command: Command to run (serialdump, serialdown, etc.)
            cmd_args: Command arguments
        
        Returns:
            True if successful
        """
        # First, upload boot file
        if not self.upload(boot_file):
            print("[!] Failed to boot device")
            return False
        
        # Re-open serial port for command mode
        self.open()
        
        # Wait a bit for boot to complete
        time.sleep(0.5)
        
        # Clear any pending data and send newline to trigger fresh prompt
        self.ser.reset_input_buffer()
        self.ser.write(b"\n")
        termios.tcdrain(self.ser.fileno())
        time.sleep(0.1)
        
        # Handle the command
        if command == "serialdump":
            if len(cmd_args) < 3:
                print("[!] Usage: serialdump <partition|addr> <size> <output_file>")
                return False
            target, size, output_file = cmd_args[0], int(cmd_args[1]), cmd_args[2]
            return self.serial_dump(target, size, output_file)
        
        elif command == "serialdown":
            if len(cmd_args) < 2:
                print("[!] Usage: serialdown <partition|addr> <input_file>")
                return False
            target, input_file = cmd_args[0], cmd_args[1]
            return self.serial_download(target, input_file)
        
        elif command == "gx_otp":
            if len(cmd_args) < 1:
                print("[!] Usage: gx_otp <read|tread> <address> <length> [output_file]")
                return False
            
            subcmd = cmd_args[0]
            if subcmd == "read":
                if len(cmd_args) < 4:
                    print("[!] Usage: gx_otp read <address> <length> <output_file>")
                    return False
                addr, length, output_file = int(cmd_args[1]), int(cmd_args[2]), cmd_args[3]
                return self.gx_otp_read(addr, length, output_file)
            
            elif subcmd == "tread":
                if len(cmd_args) < 3:
                    print("[!] Usage: gx_otp tread <address> <length>")
                    return False
                addr, length = int(cmd_args[1]), int(cmd_args[2])
                result = self.gx_otp_tread(addr, length)
                if result:
                    print(f"[+] GX OTP data:\n{result}")
                    return True
                return False
            else:
                print(f"[!] Unknown gx_otp subcommand: {subcmd}")
                return False
        
        elif command == "sflash_otp":
            if len(cmd_args) < 1:
                print("[!] Usage: sflash_otp <status|getregion|read> [args...]")
                return False
            
            subcmd = cmd_args[0]
            if subcmd == "status":
                result = self.sflash_otp_status()
                if result:
                    print(f"[+] SPI Flash OTP:\n{result}")
                    return True
                return False
            
            elif subcmd == "getregion":
                result = self.sflash_otp_getregion()
                if result:
                    print(f"[+] SPI Flash OTP:\n{result}")
                    return True
                return False
            
            elif subcmd == "read":
                if len(cmd_args) < 4:
                    print("[!] Usage: sflash_otp read <address> <length> <output_file>")
                    return False
                addr, length, output_file = int(cmd_args[1]), int(cmd_args[2]), cmd_args[3]
                return self.sflash_otp_read(addr, length, output_file)
            
            else:
                print(f"[!] Unknown sflash_otp subcommand: {subcmd}")
                return False
        
        elif command == "compare":
            if len(cmd_args) < 2:
                print("[!] Usage: compare <src_file> <dst_file>")
                return False
            return self.compare_files(cmd_args[0], cmd_args[1])
        
        elif command == "usbdump":
            if len(cmd_args) < 3:
                print("[!] Usage: usbdump <partition|addr> <size> <filename>")
                print("[!] Note: filename is on USB drive attached to device")
                return False
            target, size, filename = cmd_args[0], int(cmd_args[1]), cmd_args[2]
            return self.usb_dump(target, size, filename)
        
        elif command == "usbdown":
            if len(cmd_args) < 2:
                print("[!] Usage: usbdown <partition|addr> <filename>")
                print("[!] Note: filename is on USB drive attached to device")
                return False
            target, filename = cmd_args[0], cmd_args[1]
            return self.usb_download(target, filename)
        
        elif command == "flash":
            if len(cmd_args) < 1:
                print("[!] Usage: flash <erase|badinfo|eraseall> [args...]")
                return False
            
            subcmd = cmd_args[0]
            if subcmd == "erase":
                if len(cmd_args) < 2:
                    print("[!] Usage: flash erase [nospread] <partition|addr> [length]")
                    return False
                
                # Check for nospread flag
                nospread = False
                args_start = 1
                if cmd_args[1] == "nospread":
                    nospread = True
                    args_start = 2
                
                if len(cmd_args) <= args_start:
                    print("[!] Usage: flash erase [nospread] <partition|addr> [length]")
                    return False
                
                target = cmd_args[args_start]
                length = int(cmd_args[args_start + 1]) if len(cmd_args) > args_start + 1 else None
                return self.flash_erase(target, length, nospread)
            
            elif subcmd == "badinfo":
                return self.flash_badinfo()
            
            elif subcmd == "eraseall":
                return self.flash_eraseall()
            
            else:
                print(f"[!] Unknown flash subcommand: {subcmd}")
                print("[!] Available: erase, badinfo, eraseall")
                return False
        
        else:
            print(f"[!] Unknown command: {command}")
            print("[*] Available commands:")
            print("    serialdump, serialdown  - Serial flash read/write")
            print("    usbdump, usbdown        - USB flash read/write")
            print("    gx_otp                  - GX OTP read")
            print("    sflash_otp              - SPI Flash OTP operations")
            print("    flash                   - Flash management (erase, badinfo)")
            print("    compare                 - Compare two files (host-side)")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="libre-gxdl: Open Source GX Bootloader Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Just boot the device:
  %(prog)s -b gemini.boot -d /dev/ttyUSB0
  
  # Dump flash partition to file (via serial):
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "serialdump BOOT 65536 dump.bin"
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "serialdump 0x0 4194304 full_flash.bin"
  
  # Write file to flash (via serial - DANGEROUS!):
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "serialdown LOGO logo.bin"
  
  # Dump/write via USB drive attached to device:
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "usbdump KERNEL 2752512 kernel.bin"
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "usbdown LOGO logo.bin"
  
  # Read GX OTP (One-Time Programmable) memory:
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "gx_otp tread 0 32"
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "gx_otp read 0 64 otp.bin"
  
  # Read SPI Flash OTP:
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "sflash_otp status"
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "sflash_otp getregion"
  
  # Flash management:
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "flash badinfo"
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "flash erase LOGO"
  
  # Compare two files (host-side):
  %(prog)s -b gemini.boot -d /dev/ttyUSB0 -c "compare dump1.bin dump2.bin"
  
Commands:
  Serial Transfer:
    serialdump <partition|addr> <size> <file> - Dump flash to host file
    serialdown <partition|addr> <file>        - Write host file to flash
  
  USB Transfer (files on USB drive attached to device):
    usbdump <partition|addr> <size> <file>    - Dump flash to USB file
    usbdown <partition|addr> <file>           - Write USB file to flash
  
  GX OTP Memory:
    gx_otp tread <addr> <len>                 - Read OTP (text hex dump)
    gx_otp read <addr> <len> <file>           - Read OTP (binary file)
  
  SPI Flash OTP:
    sflash_otp status                         - Show OTP status
    sflash_otp getregion                      - Show OTP region info
    sflash_otp read <addr> <len> <file>       - Read OTP to file
  
  Flash Management:
    flash badinfo                             - Show bad block info
    flash erase [nospread] <partition|addr> [len] - Erase flash region
    flash eraseall                            - Erase ENTIRE flash (DANGER!)
  
  Utilities:
    compare <src_file> <dst_file>             - Compare two files (host-side)
  
Tips:
  - Power cycle the device AFTER starting this tool
  - Partitions: BOOT, TABLE, LOGO, KERNEL, ROOT, DATA
  - USB commands require USB storage connected to the device formatted as FAT32
        """
    )
    parser.add_argument("-b", "--boot", required=True, help="Boot file to upload")
    parser.add_argument("-d", "--device", required=True, help="Serial device (e.g., /dev/ttyUSB0)")
    parser.add_argument("-c", "--command", help="Bootloader command to execute after boot")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--reset-dtr", action="store_true", help="Pulse DTR to reset device")
    parser.add_argument("--reset-rts", action="store_true", help="Pulse RTS to reset device")
    parser.add_argument("--loopback-test", action="store_true", help="Test serial loopback (TX→RX)")
    
    args = parser.parse_args()
    
    if args.loopback_test:
        # Simple loopback test
        print("[*] Serial loopback test - short TX to RX pins first!")
        ser = serial.Serial(args.device, args.baud, timeout=1)
        test_data = b"LOOPBACK_TEST_12345"
        ser.write(test_data)
        ser.flush()
        time.sleep(0.1)
        response = ser.read(len(test_data) + 10)
        ser.close()
        if response == test_data:
            print(f"[+] Loopback OK: sent and received {len(test_data)} bytes correctly")
        else:
            print(f"[!] Loopback FAILED!")
            print(f"    Sent: {test_data.hex()}")
            print(f"    Got:  {response.hex() if response else 'nothing'}")
        sys.exit(0)
    
    uploader = GXUploader(args.device, args.baud, args.verbose)
    
    # Set reset options
    uploader.reset_dtr = args.reset_dtr
    uploader.reset_rts = args.reset_rts
    
    if args.command:
        # Parse command
        parts = args.command.split()
        if not parts:
            print("[!] Empty command")
            sys.exit(1)
        
        cmd = parts[0]
        cmd_args = parts[1:]
        
        success = uploader.run_command_mode(args.boot, cmd, cmd_args)
    else:
        # Just boot the device
        success = uploader.upload(args.boot)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

