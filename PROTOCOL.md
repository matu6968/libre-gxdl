# GX Bootloader Protocol Specification

**Reverse engineered from gxdl.elf via hardware sniffing and strace analysis**

## Overview

The GX bootloader upload protocol is a two-stage process used to load a bootloader into Gemini/CSKY-based devices via UART.

## Hardware Details that were used for the reverse engineering process:

- **Baud Rate**: 115200 (8N1)
- **Target**: Gemini 6702H5 (C-SKY CPU family)
- **Flash**: EN25Q32 (4 MB SPI NOR)
- **SDK**: GxLoader SDK_V2.5.0_RC6

Additionally for getting network commands working, the following hardware was used:

- **Baud Rate**: 115200 (8N1)
- **Target**: Cygnus 6706H5 (C-SKY CPU family)
- **Flash**: ZB25VQ32 (4 MB SPI NOR)
- **SDK**: GxLoader SDK_V2.5.0_RC6
- **Network Interface**: Built-in Ethernet MAC into SoC + RTL8201 PHY

## Serial Port Configuration (Critical!)

If the host is a Unix-like system (Linux/macOS/etc.) the serial port MUST be configured with specific termios settings:

```
c_iflag = INPCK          # Input parity checking (critical!)
c_oflag = 0              # No output processing
c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL
c_lflag = 0              # Raw mode
```

On Windows, only baud rate configuration matters here, any other settings can be ignored.

Additionally on Unix-like systems, call `tcflush(fd, TCIOFLUSH)` before sending and `tcdrain(fd)` after sending or a simple reset of the serial port input/output buffers on Windows.

## Protocol Flow

```
┌──────────┐                          ┌──────────┐
│   Host   │                          │  Device  │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │  <───── B8 B0 FF 58 ───────────     │  Handshake (device ready)
     │                                     │
     │  ────────── Stage 1 ──────────>     │  Header + payload + "boot" marker
     │                                     │
     │  <─────────── RUNGET ──────────     │  Device ready for stage 2
     │                                     │
     │  ────────── Stage 2 ──────────>     │  "boot" + checksum32 + size32 + content
     │                                     │
     │  <───── Boot Output (text) ────     │  Partition info, device info, boot>
     │                                     │
```

## Stage 1: Initial Bootloader Chunk

**Purpose**: Sends the initial bootstrap code to RAM

### Packet Format

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Command | `0x59` (Download command) |
| 1-2 | 2 | Length | Initial transfer size in 32-bit words |
| 3-4 | 2 | Address | `0x0000` (First block) |
| 5... | variable | Payload | Chip-dependent boot file bytes |
| ... | 4 | Marker | ASCII `"boot"` |

**Key Points**:
- For chip IDs `0x6616`, `0x3211`, `0x6701`, and `0x6705`, the length is
  `0x0800` and the payload is 8188 bytes (`boot_data[0x20:0x201C]`).
- For chip ID `0x6612`, the length is `0x1000` and the payload is 0x3fe0
  bytes (`boot_data[0x20:0x4000]`).
- Other chip IDs use length `0x0400` and a 4092-byte payload
  (`boot_data[0x20:0x101C]`).
- The `"boot"` marker is sent after the Stage 1 payload, before waiting for
  `RUNGET`; the checksum32, size32, and payload follow `RUNGET`.

### Response

Device responds with handshake (e.g., `B8 B0 FF 58`) before Stage 1, then `RUNGET` after processing.

## Stage 2: Full Boot File Transfer

**Purpose**: Sends the complete bootloader for execution

### Packet Format (148040 bytes for a 148028-byte boot file)

#### Combined wrapper (12 bytes)

The `boot` marker is sent at the end of Stage 1. After the device responds
with `RUNGET`, the host sends the remaining eight wrapper bytes followed by
the boot content:

| Combined offset | Size | Field | Description |
|----------------|------|-------|-------------|
| 4-7 | 4 | Checksum | 32-bit additive sum of boot content |
| 8-11 | 4 | Size | Boot file size, little-endian |
| 12... | variable | Content | Transformed boot content |

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
checksum32 = sum(boot_content) & 0xFFFFFFFF
```

### Response

Device outputs partition table and system information, ending with `boot>` prompt.

### Note on Apparent Metadata Field Variations

The four bytes after `"boot"` are one 32-bit little-endian checksum, not a
16-bit checksum followed by an independent type/flags field. For example,
the captured bytes `1B 34 C2 00` represent checksum `0x00C2341B`; `0x00C2`
is merely the checksum's upper 16 bits. It varies with the complete boot
payload and is not selected by SoC.

## Boot File Format

The `.boot` file has a specific structure:

| Offset | Size | Field | Example |
|--------|------|-------|---------|
| 0x00 | 4 | Magic | `"toob"` (0x746f6f62) |
| 0x04 | 2 | Version | `0x0001` |
| 0x06 | 2 | Chip ID | `0x6701` (Gemini) |
| 0x08 | 4 | Baud Rate | `0x1C200` (115200) |
| 0x0C | 20 | Reserved | Zeros on stock images; optional `GXMT` catalog (below) |
| 0x20 | ... | Code | Actual bootloader code |
| 0x2018 | 4 | Stage1 CRC | Embedded checksum |

**Note**: The magic is `"toob"` which is `"boot"` in little-endian byte order.
Open tools (`libre_gxdl.py`, `mkboot.py`) require those four bytes. Stock
`boot.elf` does **not**: it overlays the first 16 bytes as `phead` and
prints whatever integers fall out. Passing the `gxipl` source file `ipl/ipl.c` (`/* SPDX-...`) as an example yielded `magic: 53202a2f` (`/* S`), `version: 4450` (`PD`), `chip: 2d58`
(`X-`), `baudrate: 6563694c` (`Lice`) and it still waited for BootROM.
`-b /dev/null` (0 bytes) still printed a full `phead` (`magic: e4a`,
`version: 10`, `chip: 3304`, `baudrate: 393933` — leftover memory, not a
file). `libre_gxdl.py` rejects the same inputs (`Invalid boot file magic`
or `Boot file too small: 0 bytes`). Do not loosen those checks to match
vendor.

Vendor `gxdl` / BootROM UART never send bytes `0x04..0x1F` to the device:
Stage 1 payload starts at `0x20`, and Stage 2 is `"toob"` plus `boot[0x20:]`
with 28 bytes of padding. Offset 6 selects the Stage 1 window.

Stock `boot.elf` (`boot version:develop --20220107`) was tried with open `gxipl` 
`gx-universal-ipl.boot`. It printed only `magic` / `version` / `chip: 6701` /
`baudrate` and uploaded 8224 bytes. The reserved 20 bytes on that artifact
were still zero, so this did not exercise `GXMT`; vendor also accepts
non-`toob` files and `/dev/null` (above). The following `EBUNDLE` is the open
IPL: vendor Stage 2 is the same 8 KiB IPL container with no `GXUB`/`GXBC`
payload. Tools implementing this spec should add a bootcode selection option like `libre_gxdl.py --bootcode` when it detects a `GXBC` payload for
Stage 2; do not expect vendor gxdl to chain bootcode onto an IPL-only file.

Optional open catalog when `boot[0x0C:0x10] == "GXMT"`:

| Offset | Size | Field |
|--------|------|-------|
| 0x0C | 4 | `"GXMT"` |
| 0x10 | 1 | Version (`1`) |
| 0x11 | 1 | Extra chip-ID count (`0..6`) |
| 0x12 | 2×N | Little-endian extra chip IDs (not including offset 6) |
| .. | .. | Remaining bytes zero |

The universal UART stub keeps offset 6 as `0x6701` so stock gxdl still treats
the file as Gemini. `utils/mkboot.py --soc universal` writes `0x6705` /
`0x6616` / `0x3211` here by default (same 8 KiB Stage 1 window). Any wrap can
add IDs with `--extra-chip-id 0x6705` (repeatable; replaces the SoC default)
or keep zeros with `--no-extra-chip-ids`. Open flashers still send Stage 1
**once**. Dedicated GX6702/GX6706 images leave the 20 bytes zero unless those
flags are used. Offset 6 is not stored again in `GXMT`.

`libre_gxdl.py` prints extra IDs only when `GXMT` is present. A Gemini UART
run of `gx-universal-ipl.boot` with reserved zeros showed only
`Chip: 0x6701`, then `GXID family=gemini name=6702S5-NNNB` and sent
`gx6702-bootcode.bin` as `GXBC`. Stage 2 is always selected from `GXID`, not
from this catalog.

## Chip IDs

Different chips use different Stage 1 SRAM windows and chunk sizes after IPL initializes (see above).

| Chip ID | Description | Stage 1 size | Chunk size |
|---------|-------------|--------------|------------|
| 0x6612 | GX6612 | 0x4000 (16 KiB window, 0x3fe0 payload aka ~10 KiB IPL) | 0x2000 |
| 0x6616 | GX6616 | 0x2000 (8 KiB, 8188-byte payload) | 0x2000 |
| 0x3211 | GX3211 | 0x2000 (8 KiB, 8188-byte payload) | 0x2000 |
| 0x6701 | Gemini (GX6701, GX6702, GX6703) | 0x2000 (8 KiB, 8188-byte payload) | 0x1000 |
| 0x6705 | Cygnus (GX6705, GX6706) | 0x2000 (8 KiB, 8188-byte payload) | 0x2000 |
| Others | Default | 0x1000 (4 KiB, 4092-byte payload) | 0x1000 |

The `.boot` chip ID at offset 6 is host metadata for choosing the Stage 1
layout above. UART BootROM does not consult it on GX6702/GX6706; behavior on
GX6612/GX6616/GX3211 is unknown.

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

### Transfer Modes

The vendor downloader also supports a transfer mode flag, exposed in this tool as `-t` / `--transfer-mode`.

- `s` (default): upload the `.boot` image and boot into the downloader.
- `nns`: skip the `.boot` upload when the device is already in command mode; this matches the vendor downloader's `-t nns` behavior.

This is useful when the device is already sitting at the `boot>` prompt and you just want to issue commands without retransferring the boot image.

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

### Network TFTP (`netdump` / `netdown`)

GxLoader can dump and program flash over Ethernet. The host speaks TFTP on
UDP port **2000** (not 69). The device is the TFTP **client**; the PC is the
server. Reverse engineered from `gxdl.elf` (`tftpd_thread`, `receive_file`,
`send_file`, `send_oack`) and verified on a GX6706 (Cygnus-6706H5) with a
direct PC <--> STB Ethernet cable.

This is **not** RFC-compliant TFTP. Reimplementations that follow RFC 1350
TIDs, OACK-on-WRQ, or the empty last DATA packet will time out even when
the payload already transferred. Vendor `gxdl` itself fails `netdump` of an
exact `blksize` multiple for that last reason.

#### Host CLI vs device commands

Vendor `gxdl` / `libre-gxdl` flags:

| Flag | Meaning | Default |
|------|---------|---------|
| `-p` / `--pcip` | Host IPv4 used as TFTP server address | Auto-detect |
| `-s` / `--stbip` | Board IPv4 | Host IP with last octet `+ 1` |
| `--tftp-port` | Well-known TFTP port | `2000` |

The CLI command the user types is **not** what GxLoader receives:

| Host CLI | Device text command |
|----------|---------------------|
| `netdump <target> <length> <file>` | `netdump <target> <pcip> <file> <size>` |
| `netdown <target> <file>` | `partition download <target> <pcip> "<file>" <size>` |

`<target>` is a partition name (`BOOT`, `DATA`, ...) or a flash address.
`<file>` on the wire is the **basename only**. Size may be decimal or `0x...`.

Other `boot>` net helpers (passthrough, not required for dump/write):
`config ip`, `config tftpport`, `net configip`, `net configport`,
`net configshow`, `net ping`, `net arp`, `net tftp`.

#### Link bring-up

Do this **before** the TFTP listen socket is needed for the transfer, in
this order:

1. Bind a UDP socket to `(pcip, 2000)` (`SO_REUSEADDR`). Stay on this port
   for the whole transfer (see TID note below).
2. Send `config ip <stbip>\n` and wait for `boot>`.
3. Send `config tftpport 2000\n` and wait for `boot>`. Until this runs,
   some loaders still use port 69.
4. Start listening, then send `netdump` / `partition download`.

GxLoader pings `pcip` before opening TFTP. ICMP success does not imply UDP
2000 is open (host firewall). Direct Ethernet works; a Wi-Fi STA path often
ARPs and then drops TFTP (AP isolation). Bind to the Ethernet address, not
`0.0.0.0`, when the PC has more than one NIC. A system `in.tftpd` on port 69
is unrelated and can stay running.

Some boards default to `192.168.120.3/24` in GxLoader. The PC NIC used for
the cable must be on that subnet (for example `192.168.120.100/24`, no
default route on that link).

#### TFTP packet format

All TFTP multi-byte fields are **big-endian** (network order), unlike the
UART boot protocol.

| Opcode | Value | Direction (netdump/netdown) |
|--------|-------|-----------------------------|
| RRQ | `0x0001` | Device -> host (`netdown`) |
| WRQ | `0x0002` | Device -> host (`netdump`) |
| DATA | `0x0003` | Device -> host on dump; host -> device on down |
| ACK | `0x0004` | Opposite of DATA / WRQ |
| ERROR | `0x0005` | Either |
| OACK | `0x0006` | Host -> device on **RRQ only** |

WRQ/RRQ payload after the opcode:

```
filename \0 mode \0 [option \0 value \0 ...]
```

Mode is `octet`. GxLoader also advertises `blksize=1024`. ACK is exactly
four bytes: opcode `0x0004` and a 16-bit block number (vendor
`prepare_packet`). DATA is opcode `0x0003`, block number, then 0..blksize
payload bytes.

#### TID / port (do not follow RFC 1350)

RFC servers pick a new UDP source port (TID) after the first WRQ/RRQ.
GxLoader does not. Keep the transfer on **UDP 2000** and reply to the
client's ephemeral port (observed `1026`–`1035` range). Vendor `tftpd_thread`
opens a second socket, binds it to the **same** well-known port, `connect()`s
to the client, then `send()`/`recv()` on that connected UDP socket.

#### `netdump` (device WRQ -> host)

Host CLI: `netdump BOOT 131072 boot-net.bin`  
Device: `netdump BOOT 192.168.120.100 boot-net.bin 131072`

```
Host UDP :2000                          Device
     |                                     |
     |  <──── ICMP echo (pcip) ──────────  |
     |  ──── ICMP reply ────────────────>  |
     |  <──── WRQ name, octet, blksize=1024
     |  ──── ACK block 0 (NOT OACK) ────>  |
     |  <──── DATA block 1 (1024 bytes) ─  |
     |  ──── ACK 1 ─────────────────────>  |
     |            …                        |
     |  <──── DATA block N ──────────────  |
     |  ──── ACK N ─────────────────────>  |
     |     (no empty DATA N+1)             |
```

Serial text around the transfer:

```
Write from partition 'BOOT' ...
Reply from 192.168.120.100 : icmp_seq = N
Dumpping into (boot-net.bin)...
tftp finished boot-net.bin. Partition: BOOT,length: 131072
```

**WRQ must be ACKed with block 0. Do not send OACK.** Vendor
`receive_file()` does the same. If the host OACKs `blksize=1024`, the device
ACKs block 0 and then **never sends DATA** (confirmed on GX6706).

After ACK 0, DATA blocks are 1024 bytes even though the option was ignored.
Adopt `blksize` from the first DATA payload length if it is larger than 512.
ACK every accepted block; re-ACK the previous block on duplicate DATA.

If a second WRQ arrives (device retry), restart the file (ACK 0, block 1,
truncate). On 1 s DATA timeout, re-ACK the last block, up to 8 times
(vendor prints `retrying %d more times.` then `timeout exit`).

**Last block:** RFC 1350 requires a DATA shorter than `blksize`, including a
zero-length packet when the file length is an exact multiple. GxLoader
**omits** that empty packet and prints `tftp finished` as soon as the last
full block is ACKed. `BOOT` at 128 KiB is 128×1024; `DATA` at 1280 KiB is
1280×1024. Stop when:

- DATA length `< blksize`, or
- bytes received `>=` the size from the `netdump` command, or
- eight DATA timeouts fire after a last full block and
  `received % blksize == 0`.

Waiting for the empty packet is why vendor `gxdl` `netdump` of `BOOT`
reports `timeout exit` after the device already finished.

#### `netdown` (device RRQ ← host)

Host CLI: `netdown DATA data-ref.bin` (writes flash; confirm or `-y`)  
Device: `partition download DATA 192.168.120.100 "data-ref.bin" 1310720`

```
Host UDP :2000                          Device
     |                                     |
     |  <──── ICMP echo (pcip) ──────────  |
     |  ──── ICMP reply ────────────────>  |
     |  <──── RRQ name, octet, blksize=1024
     |  ──── OACK blksize=1024 ─────────>  |
     |  <──── ACK block 0 (optional) ────  |
     |  ──── DATA block 1 (1024 bytes) ─>  |
     |  <──── ACK 1 ─────────────────────  |
     |            ...                      |
     |  ──── DATA block N ──────────────>  |
     |  <──── ACK N ─────────────────────  |
     |     (empty DATA N+1 optional)       |
```

Serial text around the transfer:

```
Reply from 192.168.120.100 : icmp_seq = N
Getting (data-ref.bin)...
Receiving.....................
tftp finished data-ref.bin. address: 0x...,transfer_len: 1310720
protect len: 0x0
Erase partition 'DATA' ...
Write to partition 'DATA' ...
```

**RRQ does use OACK.** Vendor `tftpd_thread` always `send_oack("blksize", ...)`
then `send_file()`. Retry the OACK on timeout (vendor: 9 attempts, then
`timeout exit`). `send_oack` does not strictly parse ACK 0 before
`send_file`; if ACK 0 never arrives, still start DATA at the requested
`blksize`. Retransmit each DATA up to 8 times until the matching ACK.

After TFTP, GxLoader erases and programs the partition. A successful
round-trip on GX6706 `DATA` (1310720 bytes) matched a pre-write dump
byte-for-byte.

**Warning:** `netdown` writes flash and can brick the device. Dump a
reference first. Prefer `DATA` over `BOOT`/`KERNEL`/`TABLE` for tests.

#### Extra `boot>` net commands

`net <args>` is forwarded as text. Useful for debugging the link before
TFTP: `net ping <pcip>`, `net configshow`.

### Config-file execution (`load_conf_down`)

The vendor downloader exposes a configuration-loading command, `load_conf_down`, whose behavior is mirrored in this tool.

**Command Format:**
```
load_conf_down <config_file> <transport> [transport_path]
```

**Behavior:**
1. The host opens the config file and reads it line by line.
2. Each non-comment line is parsed as a downloader command.
3. Commands are executed sequentially in the current `boot>` session.

**Supported command forms:**
- `serialdown <partition|address> <file>`
- `serialdump <partition|address> <size> <file>`
- `usbdown <partition|address> <file>`
- `usbdump <partition|address> <file>`
- `flash erase [nospread] <partition|address> [length]`
- `flash badinfo`
- `flash eraseall`
- `flash scrub <address> <length>`
- `flash scrub all`
- `flash mark bad <address>`

The parser is intentionally lightweight and follows the simple command-per-line style visible in the vendor binary's config-loading path.

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

**Lock OTP - DANGEROUS / irreversible (untested on hardware):**

Vendor `Boot::cmd_parser` maps CLI `sflash_otp lock` to device
`sflash_otp %s` -> `sflash_otp lock`. Text-mode only; no `~sta~` stream.
On parts that implement it this permanently locks the SPI OTP.

**Set region - DANGEROUS (untested on hardware):**

CLI `sflash_otp setregion <num>` (exactly three argv tokens) becomes
`sflash_otp %s %s` -> `sflash_otp setregion <num>`. The number is passed
as the original token, not reformatted. Device help:
`sflash_otp <lock|status|erase|setregion num|getregion>`.

### Flash scrub / mark bad (NAND, untested on hardware)

These exist in vendor `boot_usage_detailed`:

```
flash scrub <flash addr> <length>
flash scrub all
flash mark bad <flash addr>
```

`Boot::cmd_parser` does **not** rewrite them. After the named commands
(`netdown`, `sflash_otp`, `load_conf_down`, ...) the leftover argv is
rejoined with `argv2str` and sent to GxLoader as-is. Reimplementations
should send the same strings.

Vendor help also prints:

```
Note: scrub command is DANGEROUS!!! Factory set bad blocks will be lost
```

Embedded NOR GxLoader help tables inside `gxdl.elf` often omit scrub/mark
(they sit next to `flash oobread` / `oobwrite` on NAND images). The device
may reject the command on SPI NOR. Not exercised on the GX6706.

### Available Partitions (will differ by device)

Example map from one Gemini SDK image with a 64 KB `BOOT`. Other images
place `TABLE` after a 128 KB `BOOT` (TABLE at `0x20000`). Use the on-flash
TABLE; do not infer size from the SoC name. Additionally there may be more partitions available (such as a additional `V_OEM` partition specifiying device properties)

| ID | Name | Address | Size | Description |
|----|------|---------|------|-------------|
| 0 | BOOT | 0x000000 | 64 KB | IPL (8 KB) and GxLoader bootloader (56 KB) |
| 1 | TABLE | 0x010000 | 512 B | Partition table |
| 2 | LOGO | 0x010200 | 65024 B | Boot logo (JPEG, decoded by hardware JPEG decoder on device) |
| 3 | KERNEL | 0x020000 | 2688 KB | eCos 3.x RTOS kernel + embedded romfs |
| 4 | ROOT | 0x2c0000 | 832 KB | Root filesystem (cramfs) |
| 5 | DATA | 0x390000 | 448 KB | User data partition (minifs)

On-flash TABLE (magic `AA BC DE FA`, then a count byte, then 24-byte
entries) stores `name[8]` plus four **big-endian** `u32` fields: total size,
used size, start address, flags. A verified Cygnus 6706H5 4 MB map (TABLE at
`0x20000` after a 128 KB `BOOT`):

| ID | Name | Address | Size | Description |
|----|------|---------|------|-------------|
| 0 | BOOT | 0x000000 | 128 KB | IPL and GxLoader |
| 1 | TABLE | 0x020000 | 512 B | Partition table |
| 2 | LOGO | 0x020200 | 65024 B | Boot logo |
| 3 | KERNEL | 0x030000 | 2176 KB | eCos kernel + romfs |
| 4 | ROOT | 0x250000 | 448 KB | Root filesystem (`hsqs` squashfs) |
| 5 | DATA | 0x2c0000 | 1280 KB | User data (minifs) |

Use this table (or `info` / a full dump) for `netdump` lengths. Do not copy
the 64 KB `BOOT` example onto a 128 KB board.

**Note:** These devices typically run eCos 3.x RTOS due to low flash sizes (typically 4MB). The kernel includes statically 
linked utilities like SDL 2 (UI), ntfs-3g (NTFS driver for USB storage), WiFi/Ethernet firmware, etc from analysis of the KERNEL partition.

Additionally some devices may come with a 64 KB `BOOT` partition while others with 128 KB `BOOT` partitions, the main difference
between then is the support for USB firmware upgrades by loading one of `recovery.rcv`, `recovery_all.rcv`, `recovery_all_force.rcv` (or by the chipset name for example `gx6706.rcv` or `gx6706_all.rcv`) files on
a FAT32 USB drive and booting the setup box with it which will replace the entire firmware stored on flash.

## Notes

1. The handshake pattern may vary (`B0 B0 58`, `B0 30 FF 58`, `00 B0 B0 58` or `B8 B0 FF 58`)
2. Some devices require DTR/RTS reset pulse to enter bootloader mode
3. The protocol has no error recovery - if a stage fails, restart from beginning
4. UART boot multi-byte values are little-endian. TFTP opcodes/block numbers
   and on-flash TABLE size/start fields are big-endian.
5. **Critical**: The INPCK termios flag MUST be set for reliable communication
6. The ASCII `"boot"` marker must be sent after the Stage 1 payload, before
   waiting for `RUNGET`.

### IPL noise and tolerant synchronization

The IPL may emit diagnostic bytes around both synchronization responses. The
host must not require the handshake to arrive as one contiguous read or assume
that all bytes before it are meaningful. A handshake is recognized when a
`0x58` terminator has at least two preceding bytes and the candidate sequence's
first byte is `0x00`, `0xB0`, or `0xB8`; this accepts the observed forms even
when they are split across reads. Once detected, discard buffered IPL output
before sending Stage 1 and respond immediately.

`RUNGET` detection is similarly tolerant. Accept, in order:

- contiguous `RUNGET` (case-insensitive);
- standalone `RUN` and `GET` tokens separated by non-alphanumeric bytes;
- `R`, `U`, `N`, `G`, `E`, `T` with at most four non-alphanumeric bytes between
  adjacent letters; and
- the letters in order with no more than 40 received bytes between adjacent
  letters, for captures polluted by IPL text (for example
  `19RUkgd:3\r\nNGET`).

Do not treat arbitrary occurrences embedded in longer alphanumeric words as
standalone tokens. If `RUN` is received without `GET`, a short silence may be
treated as success for devices that omit the second token.

## Troubleshooting

If the device doesn't respond with RUNGET after Stage 1:

1. **Check termios settings**: On Linux/macOS systems (or any other Unix-like system that has termios), the INPCK flag must be set
2. **Check payload size**: It must match the chip-dependent Stage 1 layout above
3. **Check Stage 2 marker**: `"boot"` must follow the Stage 1 payload before
   waiting for `RUNGET`
4. **Check timing**: Don't add unnecessary delays between writes
5. **Verify handshake**: Wait for the 0x58 byte before sending
