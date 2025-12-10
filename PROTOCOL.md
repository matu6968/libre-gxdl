# GX Bootloader Protocol Specification

**Reverse engineered from gxdl.elf via hardware sniffing and strace analysis**

## Overview

The GX bootloader upload protocol is a two-stage process used to load a bootloader into Gemini/CSKY-based devices via UART.

## Hardware Details that were used for the reverse engineering process:

- **Baud Rate**: 115200 (8N1)
- **Target**: Gemini 6702H5 (C-SKY CPU family)
- **Flash**: EN25Q32 (4 MB SPI NOR)
- **SDK**: GxLoader SDK_V2.5.0_RC6

## Serial Port Configuration (Critical!)

The serial port MUST be configured with specific termios settings:

```
c_iflag = INPCK          # Input parity checking (critical!)
c_oflag = 0              # No output processing
c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL
c_lflag = 0              # Raw mode
```

Additionally, call `tcflush(fd, TCIOFLUSH)` before sending and `tcdrain(fd)` after sending.

## Protocol Flow

```
┌──────────┐                          ┌──────────┐
│   Host   │                          │  Device  │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │  <───── B8 B0 FF 58 ───────────   │  Handshake (device ready)
     │                                     │
     │  ────── Stage 1 (8197 bytes) ──>   │  Header + Payload + "boot" terminator
     │                                     │
     │  <─────────── RUNGET ──────────   │  Device ready for stage 2
     │                                     │
     │  ────────── Stage 2 ──────────>    │  Metadata + boot content
     │                                     │
     │  <───── Boot Output (text) ─────   │  Partition info, device info, boot>
     │                                     │
```

## Stage 1: Initial Bootloader Chunk

**Purpose**: Sends the initial bootstrap code to RAM

### Packet Format (8197 bytes total)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Command | `0x59` (Download command) |
| 1-2 | 2 | Length | `0x0800` LE (2048 words) |
| 3-4 | 2 | Address | `0x0000` (First block) |
| 5-8192 | 8188 | Payload | Boot file bytes `[0x20:0x201C]` |
| 8193-8196 | 4 | Terminator | ASCII `"boot"` |

**Key Points**:
- Payload is `boot_data[0x20:0x201C]` = 8188 bytes (includes embedded checksum)
- The `"boot"` terminator is REQUIRED and must be sent after the payload
- Total: 5 (header) + 8188 (payload) + 4 (terminator) = 8197 bytes

### Response

Device responds with handshake (e.g., `B8 B0 FF 58`) before Stage 1, then `RUNGET` after processing.

## Stage 2: Full Boot File Transfer

**Purpose**: Sends the complete bootloader for execution

### Packet Format (148040 bytes for a 148028-byte boot file)

#### Wrapper (12 bytes)

| Offset | Size | Field | Value | Description |
|--------|------|-------|-------|-------------|
| 0-3 | 4 | Magic | `"boot"` | Transfer marker |
| 4-5 | 2 | Checksum | 16-bit sum | Sum of boot content (mod 0x10000) |
| 6-7 | 2 | Type | `0x00C2` | Type/flags (194 decimal) |
| 8-11 | 4 | Size | Boot file size | Little-endian |

#### Boot Content (boot_size bytes)

The boot content is a modified version of the original boot file:

```
Original:  [toob][header bytes 4-31][code from 0x20...]
Sent:      [toob][code from 0x20...][28 bytes zero padding]
```

**Checksum Calculation**:
```python
boot_content = boot_data[0:4] + boot_data[0x20:]  # "toob" + code
boot_content += bytes(boot_size - len(boot_content))  # Pad to original size
checksum16 = sum(boot_content) & 0xFFFF
```

### Response

Device outputs partition table and system information, ending with `boot>` prompt.

## Boot File Format

The `.boot` file has a specific structure:

| Offset | Size | Field | Example |
|--------|------|-------|---------|
| 0x00 | 4 | Magic | `"toob"` (0x746f6f62) |
| 0x04 | 2 | Version | `0x0001` |
| 0x06 | 2 | Chip ID | `0x6701` (Gemini) |
| 0x08 | 4 | Baud Rate | `0x1C200` (115200) |
| 0x0C | 20 | Reserved | Zeros |
| 0x20 | ... | Code | Actual bootloader code |
| 0x2018 | 4 | Stage1 CRC | Embedded checksum |

**Note**: The magic is `"toob"` which is `"boot"` in little-endian byte order.

## Chip IDs

Different chips use different chunk sizes:

| Chip ID | Description | Chunk Size |
|---------|-------------|------------|
| 0x6612 | GX6612 | 0x2000 |
| 0x6616 | GX6616 | 0x2000 |
| 0x3211 | GX3211 | 0x2000 |
| 0x6701 | Gemini (6702H5) | 0x1000 |
| 0x6705 | GX6705 | 0x2000 |
| Others | Default | 0x1000 |

## Usage

```bash
# Using the gx_upload.py tool
python3 tools/gx_upload.py -b gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0 -v

# The device needs to be in BootROM mode (typically within less then a second after power-on)
```

## Device Output Example

After successful boot:
```
ONOR Flash, model: EN25Q32, size: 4 MB
Partition Version :  102
Partition Count   :  6
...
GxLoader SDK_V2.5.0_RC6 sdk_dev (966f4738...) Thu Dec 21 10:43:17 CST 2023

public id   : 7f08ab7154378bad
cpu family  : CSKY
chip model  : gemini
board type  : 6702H5
memory size : 64 MB
Flash type  : EN25Q32
Flash size  : 4 MB
cpu freq    : 594 MHz
memory freq : 672 MHz
boot>
```

## Files

- `libre_gxdl.py` - Python upload tool
- `tools/logger.py` - Hardware sniffer for protocol analysis (use this to capture the packets if it doesn't work for your device and open an issue with the captured packets)
- `tools/packets/` - Captured packet dumps (reference from a GX6702 device)
- `loaders/gemini-6702H5-sflash-24M.boot` - Reference boot file (extracted from the gxdownloader_boot utilities)
- `tools/original-binaries/boot.elf` - Original Linux binary of the gxdl.elf utility obtained from https://github.com/McMCCRU/gx6605s_linux_fw_build/blob/master/build_linux_fw/gxdownloader_linux/boot.elf, it has the version "boot version:develop --20220107" which works with newer GX series devices (used for reference, can be used to analyze the protocol further for other devices, not required for the Python tool to work)
- `tools/original-binaries/boot.exe` - Original Windows binary of the gxdl.exe utility obtained from https://dvbpro.ru/wp-content/uploads/2018/11/gxdownloader_boot_v2.1.3.zip which also contains a GUI from the .zip, it has the version "boot version:develop --20220107" which works with newer GX series devices (used for reference, can be used to analyze the protocol further for other devices on Windows, not required for the Python tool to work)

## Bootloader Command Protocol

After successful boot, the device presents a `boot>` prompt. Commands can be sent as plain text followed by newline.

### Serial Dump (serialdump)

Dumps flash contents to the host.

**Command Format:**
```
serialdump <partition|address> <size>
```

**Protocol:**
1. Host sends: `serialdump BOOT 65536\n`
2. Device echoes command and status
3. Device sends marker: `~sta~`
4. Device sends raw binary data in 1024-byte chunks
5. Device sends marker: `~crc~` + 4-byte CRC (little-endian)
6. Device sends marker: `~fin~`
7. Device returns to `boot>` prompt

**Transfer Rate:** ~11 KB/s at 115200 baud

**Example:**
```bash
# Dump BOOT partition (64KB)
gx_upload.py -b gemini.boot -d /dev/ttyUSB0 -c "serialdump BOOT 65536 dump.bin"

# Dump full flash (4MB) - takes ~7 minutes
gx_upload.py -b gemini.boot -d /dev/ttyUSB0 -c "serialdump 0x0 4194304 full.bin"
```

### Serial Download (serialdown)

Writes data to flash.

**Command Format:**
```
serialdown <partition|address> <size>
```

**Protocol:**
1. Host sends: `serialdown BOOT 65536\n`
2. Device echoes command and prepares flash
3. Device sends marker: `~sta~`
4. Host sends raw binary data in 1024-byte chunks
5. Device sends marker: `~crc~`
6. Host sends 4-byte checksum (see below)
7. Device sends marker: `~fin~`
8. Device erases and writes flash
9. Device reboots and shows partition table

**Transfer Checksum (Reverse Engineered from gxdl.elf):**
The device uses a custom XOR-sum checksum algorithm:

```python
KEY = [0x12, 0x34, 0x56, 0x78]
checksum = sum(KEY[i % 4] ^ data[i] for i in range(len(data)))
# Send as 4 bytes, big-endian
```

| Component | Value |
|-----------|-------|
| XOR Key | `0x12, 0x34, 0x56, 0x78` |
| Algorithm | `sum(key[i%4] ^ data[i])` |
| Byte Order | Big-endian |

The checksum is NOT CRC32. It's a simple XOR-sum using a repeating 4-byte key.

**Warning:** Writing to flash can brick the device! Always have a backup.

### GX OTP Commands

**Read OTP (text output):**
```
gx_otp tread <address> <length>
```
Returns hex dump of OTP memory to terminal.

**Read OTP (binary file):**
```
gx_otp read <address> <length>
```
Uses the same `~sta~/~crc~/~fin~` protocol as serialdump.

**Write OTP (binary file) - DANGEROUS / irreversible:**
```
gx_otp write <address> <length>
```
Protocol (mirrors serialdown):
1. Host sends command with address and length.
2. Device echoes and sends `~sta~`.
3. Host sends raw data (1024-byte chunks).
4. Device sends `~crc~`.
5. Host sends 4-byte GX checksum (big-endian) using the same XOR-sum as serialdown.
6. Device sends `~fin~` and writes OTP.

**Write OTP (hex string) - DANGEROUS / irreversible:**
```
gx_otp twrite <address> <hex_digits_string>
```
Text-mode write, response is textual (no binary stream).

### SPI Flash OTP Commands

**Status:**
```
sflash_otp status
```
Returns OTP status register value.

**Get Region:**
```
sflash_otp getregion
```
Returns the OTP region number.

**Read (binary):**
```
sflash_otp read <address> <length>
```
Uses the same `~sta~/~crc~/~fin~` protocol as serialdump.

**Write (binary) - DANGEROUS / irreversible:**
```
sflash_otp write <address> <length>
```
Assumed protocol (matches gx_otp/serialdown):
1. Host sends command with address and length.
2. Device echoes and sends `~sta~`.
3. Host sends raw data (1024-byte chunks).
4. Device sends `~crc~`.
5. Host sends 4-byte GX checksum (big-endian) using the XOR-sum key `[12 34 56 78]`.
6. Device sends `~fin~` and writes OTP.

**Erase (device-defined scope) - DANGEROUS / irreversible:**
```
sflash_otp erase
```
Text-mode command; response is textual.

### Available Partitions

| ID | Name | Address | Size | Description |
|----|------|---------|------|-------------|
| 0 | BOOT | 0x000000 | 64 KB | GxLoader bootloader |
| 1 | TABLE | 0x010000 | 512 B | Partition table |
| 2 | LOGO | 0x010200 | 65024 B | Boot logo (JPEG/PNG) |
| 3 | KERNEL | 0x020000 | 2688 KB | eCos 3.x RTOS kernel + embedded romfs |
| 4 | ROOT | 0x2c0000 | 832 KB | Root filesystem (cramfs) |
| 5 | DATA | 0x390000 | 448 KB | User data partition (minifs)

**Note:** These devices typically run eCos 3.x RTOS due to low flash sizes (typically 4MB). The kernel includes statically 
linked utilities like SDL 2 (UI), ntfs-3g (NTFS driver for USB storage), WiFi/Ethernet firmware, etc from analysis of the KERNEL partition.

## Notes

1. The handshake pattern may vary (`B0 B0 58`, `B0 30 FF 58`, or `B8 B0 FF 58`)
2. Some devices require DTR/RTS reset pulse to enter bootloader mode
3. The protocol has no error recovery - if a stage fails, restart from beginning
4. All multi-byte values are little-endian
5. **Critical**: The INPCK termios flag MUST be set for reliable communication
6. The `"boot"` terminator after Stage 1 payload is **required** - without it the device won't respond

## Troubleshooting

If the device doesn't respond with RUNGET after Stage 1:

1. **Check termios settings**: INPCK flag must be set
2. **Check payload size**: Must be 8188 bytes (`boot_data[0x20:0x201C]`)
3. **Check terminator**: `"boot"` must be sent after payload
4. **Check timing**: Don't add unnecessary delays between writes
5. **Verify handshake**: Wait for the 0x58 byte before sending

