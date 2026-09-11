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
Keep in mind that support is untested for other devices (only tested on GX6702 and GX6706) and may not work, so try at your own risk.

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
   - Chip-dependent initial payload from boot file offset 0x20
   - "boot" stage-transition marker
3. Device responds: "RUNGET"
4. Host sends Stage 2:
   - 12-byte wrapper: "boot" + checksum32 + size32
   - Boot content in 2048-byte chunks
5. Device boots and shows partition info

Usage:
  python3 libre_gxdl.py -b <bootfile> -d <serial_device> [-c <command>] [-v]
"""

import argparse
import binascii
import serial
import socket
import struct
import sys
import sysconfig
import site
import threading
import time
import os
import re
from importlib.metadata import PackageNotFoundError, files as distribution_files
from pathlib import Path

try:
    import termios
except ImportError:
    termios = None

GXID_RE = re.compile(rb"GXID family=([a-z0-9]+) name=(\S+)")
GXBC_MAGIC = 0x43425847
GXBC_ENTRY = 0x93C00000
DDR_TRAINED_FAMILIES = {"gemini", "cygnus"}
GXMT_MAGIC = b"GXMT"


def parse_int(value: str) -> int:
    """Parse decimal or 0x-prefixed hexadecimal integers."""
    return int(value, 0)


def _windows_com_number(device: str):
    """Return the COM number from COMx / \\\\.\\COMx / //./COMx, else None."""
    cleaned = device.strip().rstrip(":").replace("/", "\\")
    match = re.fullmatch(
        r"(?:\\\\\?\\)?(?:\\\\\.\\)?COM(\d+)",
        cleaned,
        flags=re.IGNORECASE,
    )
    if match:
        return int(match.group(1))
    if cleaned.isdigit():
        return int(cleaned)
    return None


def normalize_serial_device(device: str) -> str:
    """Return a pyserial port name valid on this OS.

    Windows CreateFile() often fails for bare ``COM3`` (ENOENT) unless the
    ``\\\\.\\COM3`` device namespace is used; COM10+ always needs that prefix.
    MSYS/Cygwin Python uses POSIX open() and also cannot open a bare ``COM3``.
    """
    device = device.strip()
    com_num = _windows_com_number(device)
    if com_num is None:
        return device
    platform = sys.platform
    if os.name == "nt" or platform == "win32":
        return rf"\\.\COM{com_num}"
    if platform.startswith("cygwin"):
        return f"/dev/ttyS{com_num - 1}"
    if platform.startswith(("msys", "mingw")):
        return f"//./COM{com_num}"
    return device


def serial_drain(ser) -> None:
    if ser is None:
        return
    if termios is not None:
        try:
            termios.tcdrain(ser.fileno())
            return
        except (OSError, ValueError, AttributeError, termios.error):
            pass
    try:
        ser.flush()
    except (OSError, TypeError, serial.SerialException):
        pass


def serial_flush(ser) -> None:
    if ser is None:
        return
    if termios is not None:
        try:
            termios.tcflush(ser.fileno(), termios.TCIOFLUSH)
            return
        except (OSError, ValueError, AttributeError, termios.error):
            pass
    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    except (OSError, TypeError, serial.SerialException):
        pass


def print_serial_open_help(device: str) -> None:
    if os.name == "nt":
        print("[!] Windows needs the COMx name from Device Manager -> Ports.")
        print("[!] Close other programs using the port (PuTTY, Tera Term, tio).")
    try:
        from serial.tools import list_ports
        ports = list(list_ports.comports())
    except Exception:
        ports = []
    if ports:
        print("[*] Detected serial ports:")
        for info in ports:
            print(f"    {info.device}: {info.description}")
    elif os.name == "nt":
        print("[!] No COM ports detected. Install/check the USB-UART driver.")


TFTP_RRQ = 1
TFTP_WRQ = 2
TFTP_DATA = 3
TFTP_ACK = 4
TFTP_ERROR = 5
TFTP_OACK = 6
TFTP_BLOCK = 512
TFTP_PORT = 2000


def detect_local_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    finally:
        probe.close()


def next_ipv4(ip: str) -> str:
    value = struct.unpack("!I", socket.inet_aton(ip))[0] + 1
    return socket.inet_ntoa(struct.pack("!I", value & 0xFFFFFFFF))


def parse_tftp_request(data: bytes):
    opcode = struct.unpack("!H", data[:2])[0]
    parts = data[2:].split(b"\x00")
    filename = parts[0].decode("latin-1", errors="replace") if parts else ""
    mode = parts[1].decode("latin-1", errors="replace").lower() if len(parts) > 1 else "octet"
    options = {}
    index = 2
    while index + 1 < len(parts) and parts[index]:
        options[parts[index].decode("latin-1", errors="replace").lower()] = parts[index + 1].decode("latin-1", errors="replace")
        index += 2
    return opcode, filename, mode, options


class TftpServer:
    """Minimal TFTP server matching gxdl.elf (UDP port 2000, octet/netascii).

    GxLoader's TFTP client is picky: keep the transfer on the well-known port
    instead of switching to a new TID the way RFC 1350 servers do.
    """

    def __init__(self, port: int = TFTP_PORT, timeout: float = 5.0, bind_ip: str = ""):
        self.port = port
        self.timeout = timeout
        self.bind_ip = bind_ip or ""
        self._thread = None
        self._listen = None
        self._stop = threading.Event()
        self._done = threading.Event()
        self.error = None
        self.received_path = None
        self._mode = None
        self._path = None
        self._send_data = None
        self._expected_size = None

    def start_receive(self, path: str, expected_size: int | None = None):
        self._mode = "recv"
        self._path = Path(path)
        self._expected_size = expected_size
        self._start()

    def start_send(self, path: str, data: bytes):
        self._mode = "send"
        self._path = Path(path)
        self._send_data = data
        self._start()

    def _start(self):
        self._stop.clear()
        self._done.clear()
        self.error = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout) and self.error is None

    def stop(self):
        self._stop.set()
        listen = self._listen
        if listen is not None:
            try:
                listen.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _serve(self):
        listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._listen = listen
        try:
            listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen.bind((self.bind_ip, self.port))
            listen.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    data, addr = listen.recvfrom(4 + 8192)
                except socket.timeout:
                    continue
                opcode, filename, mode, options = parse_tftp_request(data)
                print(f"[*] TFTP opcode {opcode} from {addr[0]}:{addr[1]} name={filename!r} mode={mode}")
                listen.settimeout(self.timeout)
                if self._mode == "recv" and opcode == TFTP_WRQ:
                    self._receive_file(listen, addr, options)
                    return
                if self._mode == "send" and opcode == TFTP_RRQ:
                    self._send_file(listen, addr, options)
                    return
                self._send_error(listen, addr, 4, "Unexpected TFTP opcode")
        except Exception as exc:
            self.error = str(exc)
        finally:
            try:
                listen.close()
            except OSError:
                pass
            self._done.set()

    def _ack(self, sock, addr, block: int):
        sock.sendto(struct.pack("!HH", TFTP_ACK, block), addr)

    def _send_error(self, sock, addr, code: int, message: str):
        payload = struct.pack("!HH", TFTP_ERROR, code) + message.encode("ascii", errors="replace") + b"\x00"
        sock.sendto(payload, addr)

    def _receive_file(self, sock, addr, options):
        try:
            # GxLoader advertises blksize=1024 but its WRQ path expects ACK 0,
            # not OACK. Vendor tftpd does the same in receive_file().
            advertised = int(options.get("blksize", TFTP_BLOCK)) if options else TFTP_BLOCK
            blksize = TFTP_BLOCK
            self._ack(sock, addr, 0)
            expected = 1
            retries = 0
            bytes_received = 0
            sock.settimeout(1.0)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "wb") as handle:
                while not self._stop.is_set():
                    try:
                        data, addr = sock.recvfrom(4 + max(advertised, TFTP_BLOCK, blksize))
                    except socket.timeout:
                        retries += 1
                        if retries > 8:
                            # GxLoader omits the RFC empty last DATA packet
                            # when the file length is an exact multiple of blksize.
                            if bytes_received > 0 and bytes_received % blksize == 0:
                                break
                            raise TimeoutError("timed out waiting for TFTP DATA")
                        self._ack(sock, addr, expected - 1 if expected > 1 else 0)
                        continue
                    retries = 0
                    opcode = struct.unpack("!H", data[:2])[0]
                    if opcode == TFTP_WRQ:
                        _, _, _, new_options = parse_tftp_request(data)
                        advertised = int(new_options.get("blksize", TFTP_BLOCK)) if new_options else TFTP_BLOCK
                        blksize = TFTP_BLOCK
                        self._ack(sock, addr, 0)
                        expected = 1
                        bytes_received = 0
                        handle.seek(0)
                        handle.truncate()
                        continue
                    if opcode != TFTP_DATA or len(data) < 4:
                        continue
                    block = struct.unpack("!H", data[2:4])[0]
                    chunk = data[4:]
                    if expected == 1 and len(chunk) > blksize:
                        blksize = len(chunk)
                    if block == expected:
                        handle.write(chunk)
                        bytes_received += len(chunk)
                        self._ack(sock, addr, block)
                        if len(chunk) < blksize:
                            break
                        if self._expected_size is not None and bytes_received >= self._expected_size:
                            break
                        expected = (expected + 1) & 0xFFFF
                    elif block == ((expected - 1) & 0xFFFF):
                        self._ack(sock, addr, block)
            self.received_path = str(self._path)
        except Exception as exc:
            self.error = str(exc)
        finally:
            self._done.set()

    def _recv_ack(self, sock, expected_block: int):
        try:
            ack, addr = sock.recvfrom(32)
        except socket.timeout:
            return None, None
        if len(ack) < 4:
            return None, addr
        opcode, block = struct.unpack("!HH", ack[:4])
        if opcode == TFTP_ACK and block == expected_block:
            return True, addr
        return False, addr

    def _send_file(self, sock, addr, options):
        try:
            data = self._send_data if self._send_data is not None else self._path.read_bytes()
            blksize = int(options.get("blksize", TFTP_BLOCK)) if options else TFTP_BLOCK
            sock.settimeout(1.0)
            # Vendor tftpd OACKs RRQ blksize, then send_file(). GxLoader may ACK 0
            # or start waiting for DATA; do not abort the transfer either way.
            if options:
                oack = struct.pack("!H", TFTP_OACK)
                for key, value in options.items():
                    oack += key.encode("ascii") + b"\x00" + str(value).encode("ascii") + b"\x00"
                for _ in range(9):
                    sock.sendto(oack, addr)
                    ok, new_addr = self._recv_ack(sock, 0)
                    if new_addr is not None:
                        addr = new_addr
                    if ok:
                        break
            offset = 0
            block = 1
            while not self._stop.is_set():
                chunk = data[offset:offset + blksize]
                packet = struct.pack("!HH", TFTP_DATA, block) + chunk
                acked = False
                for _ in range(9):
                    sock.sendto(packet, addr)
                    ok, new_addr = self._recv_ack(sock, block)
                    if new_addr is not None:
                        addr = new_addr
                    if ok:
                        acked = True
                        break
                if not acked:
                    if offset + len(chunk) >= len(data):
                        break
                    raise TimeoutError("timed out waiting for TFTP ACK")
                offset += len(chunk)
                if len(chunk) < blksize:
                    break
                block = (block + 1) & 0xFFFF
        except Exception as exc:
            self.error = str(exc)
        finally:
            self._done.set()


def parse_target_catalog(image: bytes):
    """Extra chip IDs from toob[0x0C:0x20], or None if the field is unused."""
    if len(image) < 0x20 or image[0x0C:0x10] != GXMT_MAGIC:
        return None
    if image[0x10] != 1 or image[0x11] > 6:
        return None
    return [struct.unpack_from("<H", image, 0x12 + index * 2)[0]
            for index in range(image[0x11])]


def header_supported_chip_ids(image: bytes):
    if len(image) < 8 or image[:4] != b"toob":
        return []
    ids = [struct.unpack_from("<H", image, 6)[0]]
    extras = parse_target_catalog(image)
    if extras:
        for chip in extras:
            if chip not in ids:
                ids.append(chip)
    return ids


def parse_gxid(buffer: bytes):
    """Parse the stage-1 GXID line. Hosts must ignore BootROM junk until this."""
    match = GXID_RE.search(buffer)
    if not match:
        return None
    return {
        "family": match.group(1).decode("ascii"),
        "name": match.group(2).decode("ascii"),
    }


def wrap_gxbc(payload: bytes, entry: int = GXBC_ENTRY) -> bytes:
    checksum = sum(payload) & 0xFFFFFFFF
    return struct.pack("<IIII", GXBC_MAGIC, len(payload), entry, checksum) + payload


def family_trains_ddr(family: str) -> bool:
    return family in DDR_TRAINED_FAMILIES


def bootcode_filename_for_family(family: str):
    if family == "gemini":
        return "gx6702-bootcode.bin"
    if family == "cygnus":
        return "gx6706-bootcode.bin"
    return None


def bootcode_build_hint(family: str) -> str:
    if family == "gemini":
        return "make bootcode"
    if family == "cygnus":
        return "make SOC=gx6706 bootcode"
    return "pass --bootcode <file>"


def select_open_ipl_stage2(gxid, bootcode_path):
    """Decide Stage 2 after GXID. Never send the UART stub as vendor GxLoader."""
    if gxid is None:
        return "vendor"
    if not family_trains_ddr(gxid["family"]):
        return "detect_only"
    if bootcode_path:
        return "gxbc"
    return "missing_bootcode"


def is_uart_ipl_stub(boot_data: bytes) -> bool:
    """Single 8 KiB UART envelope, or that prefix plus an optional GXAI catalog."""
    if len(boot_data) < 0x2020 or boot_data[:4] != b"toob":
        return False
    if len(boot_data) == 0x2020:
        return True
    return boot_data[0x2020:0x2024] == b"GXAI"


def stage1_8k_parts(boot_data: bytes):
    """Shared Gemini/Cygnus BootROM UART Stage 1: 0x59 / 0x0800 / 8188 / boot."""
    header = struct.pack("<BHH", 0x59, 0x0800, 0x0000)
    payload = boot_data[0x20:0x20 + 8188]
    return header, payload, b"boot"


class GXUploader:
    def __init__(self, device: str, baudrate: int = 115200, verbose: bool = False, skip_warnings: bool = False):
        self.verbose = verbose
        self.device = normalize_serial_device(device)
        self.baudrate = baudrate
        self.ser = None
        self.reset_dtr = False
        self.reset_rts = False
        self.skip_warnings = skip_warnings
        self.last_rx = b""
        self.last_gxid = None
        self.bootcode_path = None
        self.bootcode_dir = None
        self.boot_file = None
        self.chip_override = None
        self.pcip = None
        self.stbip = None
        self.tftp_port = TFTP_PORT

    def log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def confirm_action(self, warning: str, prompt: str = "Continue?") -> bool:
        """Prompt before running a potentially destructive erase command."""
        if self.skip_warnings:
            return True

        print(f"[!] {warning}")
        print(f"[!] {prompt} (y/N)")
        try:
            response = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("[!] Aborted")
            return False

        if response in {"y", "yes"}:
            return True

        print("[!] Aborted")
        return False

    def open(self):
        """Open serial port with exact settings matching vendor strace"""
        try:
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
        except serial.SerialException as exc:
            print(f"[!] Serial error: {exc}")
            print_serial_open_help(self.device)
            raise
        
        # Apply vendor-exact termios settings (from strace ioctl analysis)
        # Key: INPCK flag and raw mode as vendor uses. Windows has no termios;
        # pyserial already configured 8N1 above.
        if termios is not None:
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
        else:
            serial_flush(self.ser)
        
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
        - 00 B0 B0 58 (4 bytes) - seen in some logs
        - B0 30 FF 58 (4 bytes) - alternative seen in some logs
        
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
            try:
                waiting = self.ser.in_waiting
            except OSError as exc:
                print(f"[!] Serial I/O error while waiting for handshake: {exc}")
                return False
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
                        
                        # Valid if starts with 00, B0 or B8
                        if candidate[0] in (0x00, 0xB0, 0xB8):
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
        - Payload: selected from the boot file according to its chip ID
        - "boot" stage-transition marker

        The vendor uses a 0x2000-byte initial layout for 0x6616, 0x3211,
        0x6701, and 0x6705; a 0x4000-byte layout for 0x6612; and a
        0x1000-byte layout for other chip IDs.
        
        IMPORTANT: Must send quickly after handshake - device has short timeout!
        """
        self.log("Sending Stage 1 (must be fast!)...")
        
        header, payload, marker = self._build_stage1_parts(boot_data)
        packet = header + payload + marker
        
        # Send entire packet at once
        bytes_written = self.ser.write(packet)
        self.ser.flush()
        
        self.log(f"  Header: {header.hex()}")
        self.log(f"  Payload: {len(payload)} bytes")
        self.log(f"  Stage marker: {marker!r}")
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

        # Tolerant detection: prefer contiguous "RUN" and "GET" tokens,
        # but allow short non-alphanumeric separators (punctuation/newlines).
        # Avoid matching long alphabetic noise like "19RUkgd:3\r\nNGET".
        # Match R U N G E T with up to 4 non-alphanumeric chars between.
        runget_re = re.compile(rb"R[^A-Za-z0-9]{0,4}U[^A-Za-z0-9]{0,4}N[^A-Za-z0-9]{0,4}G[^A-Za-z0-9]{0,4}E[^A-Za-z0-9]{0,4}T", re.IGNORECASE | re.DOTALL)

        # Precompile token-boundary regexes for RUN and GET to avoid matching
        # these letter sequences when they're part of other words (like NGET).
        run_token_re = re.compile(rb"(^|[^A-Za-z0-9])RUN([^A-Za-z0-9]|$)")
        get_token_re = re.compile(rb"(^|[^A-Za-z0-9])GET([^A-Za-z0-9]|$)")

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

                parsed = parse_gxid(buffer)
                if parsed and not family_trains_ddr(parsed["family"]):
                    print("[+] Detection-only GXID; no DDR training (untested)")
                    self._record_runget(buffer)
                    return True

                # Check for RUN / GET as standalone tokens (not embedded)
                if not got_run and run_token_re.search(buffer):
                    print("[*] Received RUN")
                    got_run = True

                if not got_get and get_token_re.search(buffer):
                    print("[*] Received GET")
                    got_get = True

                if got_run and got_get:
                    self._record_runget(buffer)
                    return True

                # Accept RUN followed by short silence as success
                if got_run and (time.time() - last_rx_time) > 1.0:
                    print("[*] Got RUN, proceeding without explicit GET")
                    self._record_runget(buffer)
                    return True

                # Fallback: tolerant regex-based RUNGET detection
                if runget_re.search(buffer):
                    print("[*] Detected RUNGET variant (tolerant match)")
                    self._record_runget(buffer)
                    return True

                # Ordered-subsequence detection: allow RUNGET letters to appear
                # in order with small arbitrary bytes between (handles cases
                # like '19RUkgd:3\r\nNGET' where 'RU' and the 'N' are split).
                def ordered_subsequence(buf: bytes, pattern: bytes, max_gap: int = 25) -> bool:
                    idx = 0
                    last_pos = -1
                    for ch in pattern:
                        found = False
                        # search starting after last_pos
                        start = last_pos + 1
                        while start < len(buf):
                            if bytes([buf[start]]).lower() == bytes([ch]).lower():
                                # check gap
                                if last_pos == -1 or (start - last_pos) <= max_gap:
                                    last_pos = start
                                    found = True
                                    break
                                else:
                                    return False
                            start += 1
                        if not found:
                            return False
                    return True

                if ordered_subsequence(buffer, b"RUNGET", max_gap=40):
                    print("[*] Detected RUNGET variant (ordered subsequence)")
                    self._record_runget(buffer)
                    return True
            else:
                time.sleep(0.005)

        # Print what we got for debugging
        elapsed = time.time() - start_time
        if buffer:
            try:
                text = buffer.decode('latin-1')
                print(f"[!] Timeout after {elapsed:.1f}s waiting for RUNGET")
                print(f"[!] Got {len(buffer)} bytes: {repr(text[:200])}")
            except Exception:
                print(f"[!] Timeout after {elapsed:.1f}s. Got: {buffer[:200].hex()}")
        else:
            print(f"[!] Timeout after {elapsed:.1f}s - no data received from device")
            print("[!] Possible causes:")
            print("    - Stage 1 data was corrupted in transmission")
            print("    - Device is in wrong state (try power cycle)")
            print("    - Serial TX line issue (check wiring)")

        self._record_runget(buffer)
        return False

    def _record_runget(self, buffer):
        self.last_rx = bytes(buffer)
        self.last_gxid = parse_gxid(self.last_rx)
        if self.last_gxid:
            print(f"[+] GXID family={self.last_gxid['family']} "
                  f"name={self.last_gxid['name']}")

    @staticmethod
    def _build_stage2_parts(boot_data: bytes) -> tuple:
        """Build the vendor Stage 2 wrapper and transformed payload."""
        boot_size = len(boot_data)
        boot_content = boot_data[0:4] + boot_data[0x20:]
        if len(boot_content) < boot_size:
            boot_content += bytes(boot_size - len(boot_content))

        checksum32 = sum(boot_content) & 0xFFFFFFFF
        return (
            b"boot",
            struct.pack("<I", checksum32),
            struct.pack("<I", boot_size),
            boot_content,
        )

    def send_stage2(self, boot_data: bytes) -> bool:
        """
        Send Stage 2 using the vendor's wire format:

        - Continuation: 4-byte little-endian additive checksum of the payload
        - 4-byte little-endian payload size
        - Full boot content in 2048-byte chunks

        The ASCII "boot" marker is sent after the Stage 1 payload, before
        RUNGET. The apparent 0x00C2/0x00C5 type values are the upper half of
        the 32-bit checksum, not an independent SoC-specific field.
        """
        self.log("Sending Stage 2...")
        
        _magic, meta_part1, meta_part2, boot_content = self._build_stage2_parts(boot_data)
        boot_size = len(boot_data)
        checksum32 = struct.unpack("<I", meta_part1)[0]
        self.log(f"  Boot content checksum: 0x{checksum32:08X}")
        
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

    def send_payload_stage2(self, payload: bytes) -> bool:
        """Open-IPL Stage 2: checksum32 + size32 + raw payload (GXBC or GXUB)."""
        checksum32 = sum(payload) & 0xFFFFFFFF
        meta_part1 = struct.pack("<I", checksum32)
        meta_part2 = struct.pack("<I", len(payload))
        self.log(f"  Payload checksum: 0x{checksum32:08X} size={len(payload)}")
        self.ser.write(meta_part1)
        self.ser.write(meta_part2)
        chunk_size = 2048
        sent = 0
        while sent < len(payload):
            chunk = payload[sent:sent + chunk_size]
            self.ser.write(chunk)
            sent += len(chunk)
            pct = (sent * 100) // len(payload) if payload else 100
            print(f"\r  Progress: {pct}%", end="", flush=True)
        print()
        self.ser.flush()
        return True

    def _resolve_stub_bootcode(self):
        if self.bootcode_path:
            path = Path(self.bootcode_path)
            return path if path.is_file() else None
        if not self.last_gxid:
            return None
        name = bootcode_filename_for_family(self.last_gxid["family"])
        if not name:
            return None
        candidates = []
        if self.bootcode_dir:
            candidates.append(Path(self.bootcode_dir) / name)
        if self.boot_file:
            candidates.append(Path(self.boot_file).expanduser().resolve().parent / name)
        candidates.append(Path.cwd() / name)
        seen = set()
        for path in candidates:
            resolved = path.resolve() if path.exists() else path
            if resolved in seen:
                continue
            seen.add(resolved)
            if path.is_file():
                return path
        return None

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
        self.boot_file = boot_file
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
        # GXMT is host metadata; zeros here is normal. Stage 2 follows GXID.
        extras = parse_target_catalog(boot_data)
        if extras:
            listed = ", ".join(f"0x{c:04X}" for c in extras)
            print(f"    Header catalog extra IDs: {listed}")
            print("    UART Stage 1 is still sent once (offset 6 / 8 KiB stub layout)")
        
        # Pre-build Stage 1 parts based on strace analysis
        header, payload, marker = self._build_stage1_parts(boot_data)
        
        try:
            self.open()
            
            # Step 0: Reset device if requested
            self.pulse_reset()
            
            # Step 1: Wait for handshake
            if not self.wait_for_handshake():
                return False
            
            # Step 2: Send Stage 1 (matching vendor strace exactly!)
            # Vendor sends: header(5) + chip-dependent payload + boot marker
            self.log("Sending Stage 1...")
            
            # Flush buffers before sending (like vendor does)
            serial_flush(self.ser)
            
            # Send header (5 bytes)
            self.ser.write(header)
            self.log(f"  Header: {header.hex()}")
            
            # Send payload - same write as vendor
            self.ser.write(payload)
            self.log(f"  Payload: {len(payload)} bytes")

            # The vendor sends this marker before waiting for RUNGET. It is
            # not sent again with the Stage 2 continuation.
            self.ser.write(marker)
            self.log(f"  Stage marker: {marker}")
            
            serial_drain(self.ser)
            
            total_sent = len(header) + len(payload) + len(marker)
            self.log(f"  Total Stage 1: {total_sent} bytes")
            
            # Step 3: Wait for RUNGET (or detection-only GXID)
            if not self.wait_for_run_get(timeout=10.0):
                print("[!] Failed to get RUNGET response")
                print("[!] Device may have timed out - try again with faster reset")
                return False

            if self.last_gxid and not family_trains_ddr(self.last_gxid["family"]):
                print("[+] No Stage 2: this family has no open DDR init")
                return True

            # Step 4: After GXID, send family bootcode as GXBC.
            # Reconstructing this 8 KiB stub as vendor Stage 2 is a toob+8K
            # image without GXUB and halts the open IPL with EBUNDLE.
            time.sleep(0.05)  # 50ms
            bootcode = self._resolve_stub_bootcode()
            action = select_open_ipl_stage2(self.last_gxid, bootcode)
            if action == "gxbc":
                print(f"[+] Sending GXBC from {bootcode}")
                payload = wrap_gxbc(bootcode.read_bytes())
                if not self.send_payload_stage2(payload):
                    return False
            elif action == "missing_bootcode":
                name = bootcode_filename_for_family(self.last_gxid["family"])
                hint = bootcode_build_hint(self.last_gxid["family"])
                print("[!] GXID received; matching bootcode is not present")
                print(f"[!] Need {name} ({hint}) or --bootcode <file>")
                print("[!] Not sending the UART stub as Stage 2 (that causes EBUNDLE)")
                return False
            elif action == "vendor":
                if not self.send_stage2(boot_data):
                    return False
            
            # Step 5: Read response
            print("\n[+] Boot sequence complete, reading device output:")
            print("-" * 60)
            self.read_response(timeout=15.0)
            print("-" * 60)
            
            print("\n[+] Upload successful!")
            return True
            
        except serial.SerialException:
            return False
        except OSError as e:
            print(f"[!] Serial error: {e}")
            return False
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            return False
        finally:
            self.close()
    
    def _build_stage1_parts(self, boot_data: bytes) -> tuple:
        """
        Build Stage 1 parts using the vendor's chip-dependent layout.

        The length field is the initial transfer size in 32-bit words. The
        payload excludes the 0x20-byte boot header; for the 0x6612 path the
        vendor transfers 0x3fe0 bytes, while the other paths transfer the
        initial layout minus four bytes. The ``boot`` marker transitions the
        device into the Stage 2 continuation and is sent after this payload.
        """
        if len(boot_data) < 8:
            raise ValueError("boot data is too short to contain a chip ID")

        chip_id = struct.unpack("<H", boot_data[6:8])[0]
        if self.chip_override is not None and not is_uart_ipl_stub(boot_data):
            chip_id = self.chip_override
        if is_uart_ipl_stub(boot_data) or chip_id in (0x6616, 0x3211, 0x6701, 0x6705):
            return stage1_8k_parts(boot_data)
        if chip_id == 0x6612:
            transfer_size = 0x4000
            payload = boot_data[0x20:transfer_size]
        else:
            transfer_size = 0x1000
            payload = boot_data[0x20:0x20 + transfer_size - 4]

        header = struct.pack("<BHH", 0x59, transfer_size >> 2, 0x0000)
        return header, payload, b"boot"

    def wait_for_prompt(self, timeout: float = 5.0) -> bool:
        """
        Wait for 'boot>' prompt. If nothing arrives shortly, send a newline to
        coax the prompt to reappear (helps when the previous prompt was already
        consumed).
        """
        buffer = bytearray()
        start = time.time()
        poked = False
        
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
                        serial_drain(self.ser)
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
        serial_drain(self.ser)
        
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
        
        serial_drain(self.ser)
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
        serial_drain(self.ser)
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

    def parse_config_file(self, config_file: str) -> list:
        """
        Parse a simple vendor-style config file into a list of commands.

        The vendor loader expects a text file where each non-comment line is a
        downloader command, with arguments split on whitespace. This parser is
        intentionally lightweight and supports the common command forms used by
        ``load_conf_down``: ``serialdown ...``, ``usbdown ...``, ``flash erase ...``
        and similar one-line commands.
        """
        commands = []
        try:
            with open(config_file, "r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if parts:
                        commands.append(parts)
        except FileNotFoundError:
            print(f"[!] Config file not found: {config_file}")
            raise
        except OSError as exc:
            print(f"[!] Error reading config file: {exc}")
            raise

        return commands

    def run_config_commands(self, config_file: str, transport: str | None = None, transport_path: str | None = None) -> bool:
        """
        Execute a config file as a sequence of downloader commands.

        This mirrors the vendor loader's basic behavior for ``load_conf_down``:
        it reads a text config file, parses each command line, and runs the
        commands sequentially in the current bootloader session.
        """
        commands = self.parse_config_file(config_file)
        if not commands:
            print("[!] Config file contained no runnable commands")
            return False

        for parts in commands:
            command = parts[0]
            args = parts[1:]

            if command == "serialdown":
                if len(args) < 2:
                    print(f"[!] Invalid serialdown entry in config: {' '.join(parts)}")
                    return False
                target, input_file = args[0], args[1]
                if not self.serial_download(target, input_file):
                    return False
            elif command == "usbdown":
                if len(args) < 2:
                    print(f"[!] Invalid usbdown entry in config: {' '.join(parts)}")
                    return False
                target, filename = args[0], args[1]
                if not self.usb_download(target, filename):
                    return False
            elif command == "serialdump":
                if len(args) < 3:
                    print(f"[!] Invalid serialdump entry in config: {' '.join(parts)}")
                    return False
                target, size, output_file = args[0], parse_int(args[1]), args[2]
                if not self.serial_dump(target, size, output_file):
                    return False
            elif command == "flash":
                if len(args) < 1:
                    print(f"[!] Invalid flash entry in config: {' '.join(parts)}")
                    return False
                if args[0] == "erase" and len(args) >= 2:
                    nospread = args[1] == "nospread"
                    args_start = 2 if nospread else 1
                    if len(args) <= args_start:
                        print(f"[!] Invalid flash erase entry in config: {' '.join(parts)}")
                        return False
                    target = args[args_start]
                    length = parse_int(args[args_start + 1]) if len(args) > args_start + 1 else None
                    if not self.flash_erase(target, length, nospread):
                        return False
                elif args[0] == "badinfo":
                    if not self.flash_badinfo():
                        return False
                elif args[0] == "eraseall":
                    if not self.flash_eraseall():
                        return False
                elif args[0] == "scrub":
                    if len(args) == 2 and args[1] == "all":
                        if not self.flash_scrub():
                            return False
                    elif len(args) >= 3:
                        if not self.flash_scrub(args[1], args[2]):
                            return False
                    else:
                        print(f"[!] Invalid flash scrub entry in config: {' '.join(parts)}")
                        return False
                elif args[0] == "mark":
                    if len(args) < 3 or args[1] != "bad":
                        print(f"[!] Invalid flash mark entry in config: {' '.join(parts)}")
                        return False
                    if not self.flash_mark_bad(args[2]):
                        return False
                else:
                    print(f"[!] Unsupported flash command in config: {' '.join(parts)}")
                    return False
            else:
                print(f"[!] Unsupported config command: {command}")
                return False

        print(f"[+] Executed {len(commands)} commands from {config_file}")
        return True

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
        serial_drain(self.ser)
        
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

    def gx_otp_write(self, address: int, input_file: str) -> bool:
        """
        Write binary data to GX OTP.
        Protocol is assumed to mirror serialdown: command with length, ~sta~, data, ~crc~, checksum, ~fin~.
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"[!] Input file not found: {input_file}")
            return False
        except IOError as e:
            print(f"[!] Error reading file: {e}")
            return False

        size = len(data)
        print(f"[*] Writing {size} bytes to GX OTP at 0x{address:X}...")

        # Wait for prompt
        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        command = f"gx_otp write {address} {size}"
        success, extra = self.send_command(command, timeout=5.0)
        if not success:
            print("[!] Command not echoed back")
            return False

        # Wait for ~sta~
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
            print("[!] Timeout waiting for ~sta~ marker")
            return False

        self.log("Device ready, sending OTP data...")

        # Send data with GX checksum
        chunk_size = 1024
        bytes_sent = 0
        GX_KEY = bytes([0x12, 0x34, 0x56, 0x78])
        checksum = 0

        while bytes_sent < size:
            chunk = data[bytes_sent:bytes_sent + chunk_size]
            self.ser.write(chunk)

            for i, byte in enumerate(chunk):
                checksum += GX_KEY[(bytes_sent + i) % 4] ^ byte

            bytes_sent += len(chunk)
            progress = int(bytes_sent * 100 / size)
            if progress % 5 == 0:
                print(f"  Progress: {progress}%", end="\r")

        serial_drain(self.ser)
        print("  Progress: 100%")

        # Wait for ~crc~
        buffer = bytearray()
        start = time.time()
        self.log("[*] Waiting for CRC request...")
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

        # Send checksum (GX custom)
        checksum_bytes = struct.pack(">I", checksum & 0xFFFFFFFF)
        self.ser.write(checksum_bytes)
        serial_drain(self.ser)
        self.log(f"Sent checksum: 0x{(checksum & 0xFFFFFFFF):08X}")

        # Wait for completion
        buffer = bytearray()
        start = time.time()
        timeout = 60.0
        print("[*] Waiting for OTP write completion...")
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                recv = self.ser.read(self.ser.in_waiting)
                buffer.extend(recv)

                if b"~fin~" in buffer:
                    self.log("Got ~fin~ marker")
                    print("[+] GX OTP write complete!")
                    return True
                if b"boot>" in buffer:
                    print("[+] GX OTP write complete (prompt returned).")
                    return True
                if b"err" in buffer.lower():
                    print(f"[!] Error during OTP write:\n{buffer.decode('latin-1', errors='replace')}")
                    return False
            time.sleep(0.01)

        print(f"[!] Timeout waiting for completion. Received:\n{buffer.decode('latin-1', errors='replace')}")
        return False

    def gx_otp_twrite(self, address: int, hex_string: str) -> bool:
        """
        Text-based OTP write using hex digits (as provided by gxdl.elf usage).
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        command = f"gx_otp twrite {address} {hex_string}"
        result = self.text_command(command, timeout=30.0)
        if result:
            print(f"[+] GX OTP twrite response:\n{result}")
            return True
        return True

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

    def sflash_otp_write(self, address: int, input_file: str) -> bool:
        """
        Write data to SPI Flash OTP (DANGEROUS / irreversible).
        Protocol assumed to mirror serialdown/gx_otp write: command with length, ~sta~, data, ~crc~, checksum, ~fin~.
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            print(f"[!] Input file not found: {input_file}")
            return False
        except IOError as e:
            print(f"[!] Error reading file: {e}")
            return False

        size = len(data)
        print(f"[*] Writing {size} bytes to SPI Flash OTP at 0x{address:X} (DANGEROUS)...")

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        command = f"sflash_otp write {address} {size}"
        success, extra = self.send_command(command, timeout=5.0)
        if not success:
            print("[!] Command not echoed back")
            return False

        # Wait for ~sta~
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
            print("[!] Timeout waiting for ~sta~ marker")
            return False

        self.log("Device ready, sending OTP data...")

        # Send data with GX checksum
        chunk_size = 1024
        bytes_sent = 0
        GX_KEY = bytes([0x12, 0x34, 0x56, 0x78])
        checksum = 0

        while bytes_sent < size:
            chunk = data[bytes_sent:bytes_sent + chunk_size]
            self.ser.write(chunk)
            for i, byte in enumerate(chunk):
                checksum += GX_KEY[(bytes_sent + i) % 4] ^ byte
            bytes_sent += len(chunk)
            progress = int(bytes_sent * 100 / size)
            if progress % 5 == 0:
                print(f"  Progress: {progress}%", end="\r")

        serial_drain(self.ser)
        print("  Progress: 100%")

        # Wait for ~crc~
        buffer = bytearray()
        start = time.time()
        self.log("[*] Waiting for CRC request...")
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

        # Send checksum (GX custom)
        checksum_bytes = struct.pack(">I", checksum & 0xFFFFFFFF)
        self.ser.write(checksum_bytes)
        serial_drain(self.ser)
        self.log(f"Sent checksum: 0x{(checksum & 0xFFFFFFFF):08X}")

        # Wait for completion
        buffer = bytearray()
        start = time.time()
        timeout = 60.0
        print("[*] Waiting for SPI OTP write completion...")
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                recv = self.ser.read(self.ser.in_waiting)
                buffer.extend(recv)
                if b"~fin~" in buffer:
                    self.log("Got ~fin~ marker")
                    print("[+] SPI Flash OTP write complete!")
                    return True
                if b"boot>" in buffer:
                    print("[+] SPI Flash OTP write complete (prompt returned).")
                    return True
                if b"err" in buffer.lower():
                    print(f"[!] Error during SPI OTP write:\n{buffer.decode('latin-1', errors='replace')}")
                    return False
            time.sleep(0.01)

        print(f"[!] Timeout waiting for completion. Received:\n{buffer.decode('latin-1', errors='replace')}")
        return False

    def sflash_otp_erase(self) -> bool:
        """
        Erase SPI Flash OTP region (DANGEROUS / irreversible).
        """
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        command = "sflash_otp erase"
        print("[*] Erasing SPI Flash OTP region (DANGEROUS)...")
        result = self.text_command(command, timeout=30.0)
        if result:
            print(f"[+] sflash_otp erase response:\n{result}")
        return True

    def sflash_otp_lock(self) -> bool:
        """Lock SPI Flash OTP (DANGEROUS / irreversible). Vendor: sflash_otp %s."""
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        print("[!] WARNING: sflash_otp lock is irreversible on parts that support it.")
        if not self.confirm_action(
            "This will lock SPI Flash OTP.",
            "Proceed with sflash_otp lock?",
        ):
            return False

        result = self.text_command("sflash_otp lock", timeout=30.0)
        if result:
            print(f"[+] sflash_otp lock response:\n{result}")
        return True

    def sflash_otp_setregion(self, region: str) -> bool:
        """Select SPI Flash OTP region. Vendor: sflash_otp %s %s."""
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        print("[!] WARNING: sflash_otp setregion changes OTP region selection.")
        if not self.confirm_action(
            f"This will set SPI Flash OTP region to {region}.",
            "Proceed with sflash_otp setregion?",
        ):
            return False

        command = f"sflash_otp setregion {region}"
        print(f"[*] {command}")
        result = self.text_command(command, timeout=30.0)
        if result:
            print(f"[+] sflash_otp setregion response:\n{result}")
        return True

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

        if not self.confirm_action(f"This will erase {target}. Are you sure?", "Proceed with flash erase?"):
            return False
        
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

        if not self.confirm_action("This will erase the entire serial flash. Are you sure?", "Proceed with flash eraseall?"):
            return False
        
        result = self.text_command("flash eraseall", timeout=300.0)
        
        if result:
            print(f"[+] Flash eraseall output:\n{result}")
        
        return True

    def flash_scrub(self, address: str | None = None, length: str | None = None) -> bool:
        """NAND scrub. Vendor sends the CLI string through argv2str (untested here)."""
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        if address is None:
            command = "flash scrub all"
            timeout = 300.0
        else:
            if length is None:
                print("[!] Usage: flash scrub <flash addr> <length>")
                return False
            command = f"flash scrub {address} {length}"
            timeout = 120.0

        print(f"[*] {command}")
        print("[!] WARNING: scrub is DANGEROUS!!! Factory set bad blocks will be lost")
        if not self.confirm_action(
            "This will scrub NAND and can discard factory bad-block markers.",
            "Proceed with flash scrub?",
        ):
            return False

        result = self.text_command(command, timeout=timeout)
        if result:
            print(f"[+] Flash scrub output:\n{result}")
        return True

    def flash_mark_bad(self, address: str) -> bool:
        """Mark a NAND block bad. Vendor sends the CLI string through argv2str (untested here)."""
        if not self.ser or not self.ser.is_open:
            print("[!] Serial port not open")
            return False

        if not self.wait_for_prompt(timeout=2.0):
            print("[!] Not at boot> prompt")
            return False

        command = f"flash mark bad {address}"
        print(f"[*] {command}")
        print("[!] WARNING: this permanently marks a block bad in the BBT.")
        if not self.confirm_action(
            f"This will mark flash address {address} as bad.",
            "Proceed with flash mark bad?",
        ):
            return False

        result = self.text_command(command, timeout=30.0)
        if result:
            print(f"[+] Flash mark bad output:\n{result}")
        return True

    def _resolve_net_ips(self):
        pcip = self.pcip or detect_local_ip()
        stbip = self.stbip or next_ipv4(pcip)
        return pcip, stbip

    def net_configure(self, stbip: str, tftp_port: int = TFTP_PORT) -> bool:
        """Bring up GxLoader networking the way gxdl.elf does."""
        ip_result = self.text_command(f"config ip {stbip}", timeout=30.0)
        if ip_result:
            print(ip_result)
        port_result = self.text_command(f"config tftpport {tftp_port}", timeout=10.0)
        if port_result:
            print(port_result)
        return True

    def net_dump(self, target: str, size: int, output_file: str) -> bool:
        """Dump flash to the host over TFTP (device WRQ to UDP port 2000)."""
        pcip, stbip = self._resolve_net_ips()
        output_path = Path(output_file)
        if output_path.exists():
            output_path.unlink()
        print(f"[*] TFTP netdump: board {stbip} -> host {pcip}:{self.tftp_port}")
        if not self.net_configure(stbip, self.tftp_port):
            return False
        server = TftpServer(port=self.tftp_port, bind_ip=pcip, timeout=8.0)
        server.start_receive(str(output_path), expected_size=size)
        try:
            time.sleep(0.2)
            command = f"netdump {target} {pcip} {output_path.name} {size}"
            print(f"[*] {command}")
            result = self.text_command(command, timeout=max(30.0, size / 50000.0 + 20.0))
            if result:
                print(result)
            if not server.wait(timeout=8.0):
                print(f"[!] TFTP receive failed: {server.error or 'timeout'}")
                return False
            received = output_path.stat().st_size if output_path.exists() else 0
            print(f"[+] Wrote {received} bytes to {output_path}")
            return received > 0
        finally:
            server.stop()

    def net_download(self, target: str, input_file: str) -> bool:
        """Write a host file to flash over TFTP (device RRQ from UDP port 2000)."""
        if not self.confirm_action(
            "netdown writes flash over TFTP and can brick the device.",
            "Proceed with netdown?",
        ):
            return False
        pcip, stbip = self._resolve_net_ips()
        path = Path(input_file)
        data = path.read_bytes()
        print(f"[*] TFTP netdown: host {pcip}:{self.tftp_port} -> board {stbip}")
        if not self.net_configure(stbip, self.tftp_port):
            return False
        server = TftpServer(port=self.tftp_port, bind_ip=pcip, timeout=8.0)
        server.start_send(path.name, data)
        try:
            time.sleep(0.2)
            command = f'partition download {target} {pcip} "{path.name}" {len(data)}'
            print(f"[*] {command}")
            xfer_timeout = max(60.0, len(data) / 30000.0 + 30.0)
            result = self.text_command(command, timeout=xfer_timeout)
            if result:
                print(result)
            if not server.wait(timeout=xfer_timeout):
                print(f"[!] TFTP send failed: {server.error or 'timeout'}")
                return False
            print(f"[+] Sent {len(data)} bytes from {path}")
            return True
        finally:
            server.stop()

    def run_command_mode(self, boot_file: str, command: str, cmd_args: list, transfer_mode: str = "s") -> bool:
        """
        Boot device and run a command.
        
        Args:
            boot_file: Boot file to upload first
            command: Command to run (serialdump, serialdown, etc.)
            cmd_args: Command arguments
            transfer_mode: Transfer mode for the boot sequence; "s" sends the .boot image,
                while "nns" skips boot image transfer when the device is already in command mode.
        
        Returns:
            True if successful
        """
        if transfer_mode not in {"s", "nns"}:
            print(f"[!] Unsupported transfer mode: {transfer_mode}")
            return False

        if transfer_mode == "s":
            if not self.upload(boot_file):
                print("[!] Failed to boot device")
                return False
            try:
                self.open()
            except serial.SerialException:
                return False
            time.sleep(0.5)
            if self.ser is not None:
                self.ser.reset_input_buffer()
                self.ser.write(b"\n")
                serial_drain(self.ser)
                time.sleep(0.1)
        else:
            if not self.ser or not self.ser.is_open:
                try:
                    self.open()
                except serial.SerialException:
                    return False
            if not self.wait_for_prompt(timeout=2.0):
                print("[!] Not at boot> prompt; cannot use transfer mode nns")
                return False

            if self.ser is not None:
                self.ser.reset_input_buffer()
                self.ser.write(b"\n")
                serial_drain(self.ser)
                time.sleep(0.1)

        # Handle the command
        if command == "serialdump":
            if len(cmd_args) < 3:
                print("[!] Usage: serialdump <partition|addr> <size> <output_file>")
                return False
            target, size, output_file = cmd_args[0], parse_int(cmd_args[1]), cmd_args[2]
            return self.serial_dump(target, size, output_file)
        
        elif command == "serialdown":
            if len(cmd_args) < 2:
                print("[!] Usage: serialdown <partition|addr> <input_file>")
                return False
            target, input_file = cmd_args[0], cmd_args[1]
            return self.serial_download(target, input_file)
        
        elif command == "gx_otp":
            if len(cmd_args) < 1:
                print("[!] Usage: gx_otp <read|tread|write|twrite> <address> <length|file|hex> [output_file]")
                return False
            
            subcmd = cmd_args[0]
            if subcmd == "read":
                if len(cmd_args) < 4:
                    print("[!] Usage: gx_otp read <address> <length> <output_file>")
                    return False
                addr, length, output_file = parse_int(cmd_args[1]), parse_int(cmd_args[2]), cmd_args[3]
                return self.gx_otp_read(addr, length, output_file)
            
            elif subcmd == "tread":
                if len(cmd_args) < 3:
                    print("[!] Usage: gx_otp tread <address> <length>")
                    return False
                addr, length = parse_int(cmd_args[1]), parse_int(cmd_args[2])
                result = self.gx_otp_tread(addr, length)
                if result:
                    print(f"[+] GX OTP data:\n{result}")
                    return True
                return False
            elif subcmd == "write":
                if len(cmd_args) < 3:
                    print("[!] Usage: gx_otp write <address> <input_file>")
                    return False
                addr = parse_int(cmd_args[1])
                input_file = cmd_args[2]
                return self.gx_otp_write(addr, input_file)
            elif subcmd == "twrite":
                if len(cmd_args) < 3:
                    print("[!] Usage: gx_otp twrite <address> <hex_digits_string>")
                    return False
                addr = parse_int(cmd_args[1])
                hex_string = cmd_args[2]
                return self.gx_otp_twrite(addr, hex_string)
            else:
                print(f"[!] Unknown gx_otp subcommand: {subcmd}")
                return False
        
        elif command == "sflash_otp":
            if len(cmd_args) < 1:
                print("[!] Usage: sflash_otp <status|getregion|read|write|erase|lock|setregion> [args...]")
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
                addr, length, output_file = parse_int(cmd_args[1]), parse_int(cmd_args[2]), cmd_args[3]
                return self.sflash_otp_read(addr, length, output_file)
            
            elif subcmd == "write":
                if len(cmd_args) < 3:
                    print("[!] Usage: sflash_otp write <address> <input_file>")
                    return False
                addr = parse_int(cmd_args[1])
                input_file = cmd_args[2]
                return self.sflash_otp_write(addr, input_file)

            elif subcmd == "erase":
                return self.sflash_otp_erase()

            elif subcmd == "lock":
                return self.sflash_otp_lock()

            elif subcmd == "setregion":
                if len(cmd_args) < 2:
                    print("[!] Usage: sflash_otp setregion <num>")
                    return False
                parse_int(cmd_args[1])
                return self.sflash_otp_setregion(cmd_args[1])
            
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
            target, size, filename = cmd_args[0], parse_int(cmd_args[1]), cmd_args[2]
            return self.usb_dump(target, size, filename)
        
        elif command == "usbdown":
            if len(cmd_args) < 2:
                print("[!] Usage: usbdown <partition|addr> <filename>")
                print("[!] Note: filename is on USB drive attached to device")
                return False
            target, filename = cmd_args[0], cmd_args[1]
            return self.usb_download(target, filename)
        
        elif command == "load_conf_down":
            if len(cmd_args) < 2:
                print("[!] Usage: load_conf_down <config_file> <transport> [transport_path]")
                return False
            config_file = cmd_args[0]
            transport = cmd_args[1]
            transport_path = cmd_args[2] if len(cmd_args) > 2 else None
            print(f"[*] Loading config via {transport}: {config_file}")
            try:
                if self.wait_for_prompt(timeout=2.0):
                    return self.run_config_commands(config_file, transport, transport_path)
            except FileNotFoundError:
                return False
            except OSError:
                return False

            return False
        
        elif command == "flash":
            if len(cmd_args) < 1:
                print("[!] Usage: flash <erase|badinfo|eraseall|scrub|mark> [args...]")
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
                length = parse_int(cmd_args[args_start + 1]) if len(cmd_args) > args_start + 1 else None
                return self.flash_erase(target, length, nospread)
            
            elif subcmd == "badinfo":
                return self.flash_badinfo()
            
            elif subcmd == "eraseall":
                return self.flash_eraseall()

            elif subcmd == "scrub":
                if len(cmd_args) < 2:
                    print("[!] Usage: flash scrub <flash addr> <length>")
                    print("[!]        flash scrub all")
                    return False
                if cmd_args[1] == "all":
                    return self.flash_scrub()
                if len(cmd_args) < 3:
                    print("[!] Usage: flash scrub <flash addr> <length>")
                    return False
                parse_int(cmd_args[1])
                parse_int(cmd_args[2])
                return self.flash_scrub(cmd_args[1], cmd_args[2])

            elif subcmd == "mark":
                if len(cmd_args) < 3 or cmd_args[1] != "bad":
                    print("[!] Usage: flash mark bad <flash addr>")
                    return False
                parse_int(cmd_args[2])
                return self.flash_mark_bad(cmd_args[2])
            
            else:
                print(f"[!] Unknown flash subcommand: {subcmd}")
                print("[!] Available: erase, badinfo, eraseall, scrub, mark")
                return False

        elif command == "netdump":
            if len(cmd_args) < 3:
                print("[!] Usage: netdump <partition|addr> <size> <output_file>")
                return False
            target, size, output_file = cmd_args[0], parse_int(cmd_args[1]), cmd_args[2]
            return self.net_dump(target, size, output_file)

        elif command == "netdown":
            if len(cmd_args) < 2:
                print("[!] Usage: netdown <partition|addr> <input_file>")
                return False
            target, input_file = cmd_args[0], cmd_args[1]
            return self.net_download(target, input_file)

        elif command == "net":
            result = self.text_command("net " + " ".join(cmd_args), timeout=30.0)
            if result:
                print(result)
            return True
        
        else:
            print(f"[!] Unknown command: {command}")
            print("[*] Available commands:")
            print("    serialdump, serialdown  - Serial flash read/write")
            print("    usbdump, usbdown        - USB flash read/write")
            print("    gx_otp                  - GX OTP read")
            print("    sflash_otp              - SPI Flash OTP operations")
            print("    flash                   - Flash management (erase, badinfo, scrub, mark)")
            print("    compare                 - Compare two files (host-side)")
            print("    netdump, netdown, net   - Ethernet TFTP flash read/write")
            return False
        


def _install_data_roots() -> list[Path]:
    """Prefix/data roots pip uses on POSIX, macOS, and Windows."""
    roots: list[Path] = []
    for value in (sysconfig.get_path("data"), sys.prefix, getattr(site, "USER_BASE", None)):
        if value:
            roots.append(Path(value))
    try:
        user_data = sysconfig.get_path("data", sysconfig.get_preferred_scheme("user"))
    except (AttributeError, LookupError, TypeError, ValueError):
        user_data = None
    if user_data:
        roots.append(Path(user_data))
    unique: list[Path] = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return unique


def packaged_loaders_dir() -> Path:
    """Directory that contains bundled GxLoader .boot files.

    setuptools data-files use the portable key ``share/libre-gxdl/loaders``;
    pathlib turns that into ``share\\libre-gxdl\\loaders`` on Windows. The
    install root still differs (venv prefix, ``~/.local``, ``~/Library/Python``,
    ``%APPDATA%\\Python``), so search the wheel RECORD first, then every
    sysconfig data root.
    """
    candidates = [Path(__file__).resolve().parent / "loaders"]
    try:
        for entry in distribution_files("libre-gxdl") or ():
            if entry.name.endswith(".boot"):
                located = entry.locate()
                if located is not None:
                    parent = Path(located).resolve().parent
                    if parent not in candidates:
                        candidates.insert(0, parent)
                    break
    except PackageNotFoundError:
        pass
    for root in _install_data_roots():
        for relative in (
            Path("share") / "libre-gxdl" / "loaders",
            Path("libre-gxdl") / "loaders",
        ):
            path = root / relative
            if path not in candidates:
                candidates.append(path)
    for path in candidates:
        if path.is_dir() and any(path.glob("*.boot")):
            return path
    return candidates[0]


def resolve_boot_file(boot: str) -> str:
    """Return a usable boot path, including packaged loaders after install."""
    given = Path(boot)
    if given.exists():
        return boot
    loaders = packaged_loaders_dir()
    for candidate in (loaders / boot, loaders / given.name):
        if candidate.exists():
            return str(candidate)
    return boot


def build_argument_parser():
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
    gx_otp write <addr> <file>                - Write OTP (binary) [DANGEROUS]
    gx_otp twrite <addr> <hex>                - Write OTP (hex string) [DANGEROUS]
  
  SPI Flash OTP:
    sflash_otp status                         - Show OTP status
    sflash_otp getregion                      - Show OTP region info
    sflash_otp read <addr> <len> <file>       - Read OTP to file
    sflash_otp write <addr> <file>            - Write OTP (binary) [DANGEROUS]
    sflash_otp erase                          - Erase OTP region [DANGEROUS]
    sflash_otp lock                           - Lock OTP [DANGEROUS]
    sflash_otp setregion <num>                - Select OTP region [DANGEROUS]
  
  Flash Management:
    flash badinfo                             - Show bad block info
    flash erase [nospread] <partition|addr> [len] - Erase flash region
    flash eraseall                            - Erase ENTIRE flash (DANGER!)
    flash scrub <addr> <length>               - NAND scrub range [DANGEROUS]
    flash scrub all                           - NAND scrub entire device [DANGEROUS]
    flash mark bad <addr>                     - Mark NAND block bad [DANGEROUS]
  
  Utilities:
    compare <src_file> <dst_file>             - Compare two files (host-side)
    load_conf_down <config_file> <transport> [transport_path] - Load config commands to device via transport (serial, usb, etc.)
  
Tips:
  - Power cycle the device AFTER starting this tool
  - Common partitions: BOOT, TABLE, LOGO, KERNEL, ROOT, DATA (may vary by device)
  - USB commands require USB storage connected to the device formatted as FAT32
        """
    )
    parser.add_argument("-b", "--boot", required=True, help="Boot file to upload (path or name from packaged loaders)")
    parser.add_argument(
        "-d",
        "--device",
        required=True,
        help="Serial device (e.g. /dev/ttyUSB0, COM3, or \\\\.\\COM3)",
    )
    parser.add_argument("-c", "--command", help="Bootloader command to execute after boot")
    parser.add_argument("-t", "--transfer-mode", default="s", choices=["s", "nns"], help="Transfer mode for the bootloader upload: s (send boot image) or nns (skip boot image when already in command mode)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip destructive-operation confirmation prompts")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--reset-dtr", action="store_true", help="Pulse DTR to reset device")
    parser.add_argument("--reset-rts", action="store_true", help="Pulse RTS to reset device")
    parser.add_argument("--loopback-test", action="store_true", help="Test serial loopback (TX -> RX)")
    parser.add_argument("--bootcode", help="DDR bootcode binary sent as GXBC after GXID")
    parser.add_argument("--bootcode-dir", help="Directory containing gx6702-bootcode.bin / gx6706-bootcode.bin")
    parser.add_argument("--chip", type=lambda v: int(v, 0),
                        help="Override vendor GxLoader chip ID for Stage 1 size (ignored for UART stub)")
    parser.add_argument("-p", "--pcip", help="Host IP for TFTP (default: auto-detect)")
    parser.add_argument("-s", "--stbip", help="Board IP (default: host IP + 1)")
    parser.add_argument("--tftp-port", type=int, default=TFTP_PORT, help="TFTP port (vendor default 2000)")
    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()
    args.boot = resolve_boot_file(args.boot)
    
    if args.loopback_test:
        # Simple loopback test
        print("[*] Serial loopback test - short TX to RX pins first!")
        device = normalize_serial_device(args.device)
        try:
            ser = serial.Serial(device, args.baud, timeout=1)
        except serial.SerialException as exc:
            print(f"[!] Serial error: {exc}")
            print_serial_open_help(device)
            sys.exit(1)
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
    
    uploader = GXUploader(args.device, args.baud, args.verbose, skip_warnings=args.yes)
    
    # Set reset options
    uploader.reset_dtr = args.reset_dtr
    uploader.reset_rts = args.reset_rts
    uploader.bootcode_path = args.bootcode
    uploader.bootcode_dir = args.bootcode_dir
    uploader.chip_override = args.chip
    uploader.pcip = args.pcip
    uploader.stbip = args.stbip
    uploader.tftp_port = args.tftp_port
    
    if args.command:
        # Parse command
        parts = args.command.split()
        if not parts:
            print("[!] Empty command")
            sys.exit(1)
        
        cmd = parts[0]
        cmd_args = parts[1:]
        
        success = uploader.run_command_mode(args.boot, cmd, cmd_args, transfer_mode=args.transfer_mode)
    else:
        # Just boot the device
        success = uploader.upload(args.boot)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
