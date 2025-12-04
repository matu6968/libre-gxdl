# Libre NationalChip GX series downloader

This is a open source reimplemenation of the GX series downloader (also known as gxdl) by using reverse engineering at the hardware serial level + radare2.

## Features

- Supports GX series devices (only tested on GX6702, others use with caution)
- Read/writing of the flash partitions (serialdown/serialdump)
- Reading of the OTP memory (writing unimplemented, gx_otp read/tread)
- Reading of the SPI Flash status (sflash_otp status/getregion)

## Unimplemented features

- Writing of the OTP memory (gx_otp write/twrite)
- Reading/writing of the SPI Flash OTP (sflash_otp read/write)
- EEPROM reading/writing (eeprom_read/eeprom_write, does not work on all devices)
- `compare` command
- `flash` commands
- `usb*` commands
- `net*` commands
- `load_conf_down` command

## Usage

To use this tool, non-free bootloader files are required to boot the device. This might be reverse engineered at some point to remove the blobs all together for a entire open source solution.

For convinience purposes, we provide the bootloader files (extracted from the gxdownloader_boot utilities) in the `loaders` directory.

In order to detect which boot file to use, connect to the device at baud 115200 and check for `board type` in the output of the bootloader while powering the device on and from there pick the appropriate boot file from the `loaders` directory, for example:

```
...
GxLoader SDK_V2.5.0_RC6 sdk_dev (966f4738...) Thu Dec 21 10:43:17 CST 2023

public id   : 7f08ab7154378bad
cpu family  : CSKY
chip model  : gemini 
board type  : 6702H5 <-- This is the key value to determine which boot file to use
memory size : 64 MB
Flash type  : EN25Q32
Flash size  : 4 MB
cpu freq    : 594 MHz
memory freq : 672 MHz
```
To specify the bootloader file, use the `-b` argument.

```bash
python libre_gxdl.py -b loaders/gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0
```

To dump the flash partition to a file, use the `serialdump` command.
```bash
python libre_gxdl.py -b loaders/gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0 -c "serialdump BOOT 65536 dump.bin"
```

To read the OTP memory, use the `gx_otp read` command.
```bash
python libre_gxdl.py -b loaders/gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0 -c "gx_otp read 0 64 otp.bin"
```

To read the SPI Flash status, use the `sflash_otp status` command.
```bash
python libre_gxdl.py -b loaders/gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0 -c "sflash_otp status"
```

To read the SPI Flash OTP, use the `sflash_otp getregion` command.
```bash
python libre_gxdl.py -b loaders/gemini-6702H5-sflash-24M.boot -d /dev/ttyUSB0 -c "sflash_otp getregion"
```

## Protocol specifications

The protocol is reverse engineered from the gxdl.elf binary and is documented in the [PROTOCOL.md](PROTOCOL.md) file.

## Troubleshooting

If you encounter any issues and a restart does not fix it, report the issue on the GitHub repository with the following information:
- The device you are using
- The bootloader file you are using
- The command arguments
- The output of the command
- The captured packets using the original flasher and hardware UART sniffers (if available)
- What is the expected behavior using the original flasher and what is the actual behavior

To sniff the packets, use the `tools/logger.py` script with the following steps:

- Prepare 3 UART adapters (1 for the target device, 2 for the sniffing TX/RX endpoints)
- Connect the UART adapter to the target device and the sniffing TX/RX endpoints (TX of the target to TX sniffer connected under RX, RX of the target to RX sniffer connected under RX)
- Configure the script (TX_PORT and RX_PORT) to the sniffing TX/RX device names on the host machine (for example `/dev/ttyUSB1` and `/dev/ttyUSB2` as the TX/RX endpoints or for Windows `COM9` and `COM10` as the TX/RX endpoints)
- Run the script followed by the flasher and turn on the device:
```bash
python3 tools/logger.py
./tools/original-binaries/boot.elf -b <bootfile> -d <serial_device>
# or if you are on Windows:
py tools/logger.py
./tools/original-binaries/boot.exe -b <bootfile> -d <serial_device>
```
After the capture is complete, stop the script and the flasher.

```
# you should stop after the packets are captured like here:
[*] Sniffer running. Press Ctrl+C to stop.
[*] Listening on /dev/ttyUSB1 (sent)
[*] Listening on /dev/ttyUSB2 (recv)
[+] Saved recv packet (3 bytes) → packets/recv_000001.txt
[+] Saved sent packet (8193 bytes) → packets/sent_000001.txt
[+] Saved recv packet (6 bytes) → packets/recv_000002.txt
[+] Saved sent packet (148040 bytes) → packets/sent_000002.txt
[+] Saved recv packet (1424 bytes) → packets/recv_000003.txt
```
- In the issue report, include the captured packets in the `packets` directory (ideally zip the directory and attach it to the issue report).

## License

This project is licensed under the MIT License excluding the bootloader files in the `loaders` directory and the original flasher binaries in the `tools/original-binaries` directory - see the [LICENSE](LICENSE) file for details.