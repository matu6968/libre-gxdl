import tempfile
import unittest
import socket
import struct
import time
from pathlib import Path
from unittest.mock import Mock, patch

import libre_gxdl


class TestCliFeatures(unittest.TestCase):
    def _fake_serial(self):
        class FakeSerial:
            def __init__(self):
                self.is_open = True
                self.in_waiting = 0
                self.writes = []
            def reset_input_buffer(self):
                return None
            def write(self, data):
                self.writes.append(bytes(data))
                return len(data)
            def flush(self):
                return None
            def fileno(self):
                return 0
            def read(self, size=1):
                return b""
            def close(self):
                self.is_open = False
        return FakeSerial()

    def test_stage2_uses_full_checksum_and_vendor_wrapper_order(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        serial = self._fake_serial()
        uploader.ser = serial

        boot_size = 0x2423C
        target_checksum = 0x00C2341B
        boot_data = bytearray(boot_size)
        boot_data[:4] = b"toob"
        boot_data[6:8] = struct.pack("<H", 0x6701)

        # Reproduce the captured GX6702 checksum while retaining a real-size
        # boot image: boot + 1B 34 C2 00 + 3C 42 02 00.
        remaining = target_checksum - sum(boot_data[:4])
        for index in range(0x20, boot_size):
            value = min(0xFF, remaining)
            boot_data[index] = value
            remaining -= value
            if remaining == 0:
                break
        self.assertEqual(remaining, 0)

        boot_data = bytes(boot_data)
        header, payload, marker = uploader._build_stage1_parts(boot_data)
        self.assertTrue(uploader.send_stage1(boot_data))
        self.assertTrue(uploader.send_stage2(boot_data))

        self.assertEqual(serial.writes[0], header + payload + marker)
        self.assertEqual(serial.writes[1], struct.pack("<I", target_checksum))
        self.assertEqual(serial.writes[2], struct.pack("<I", boot_size))
        stage2_payload = b"".join(serial.writes[3:])
        self.assertEqual(len(stage2_payload), boot_size)
        self.assertEqual(stage2_payload[:4], b"toob")
        self.assertEqual(sum(stage2_payload), target_checksum)

    def test_stage2_checksum_is_full_width_for_repository_loaders(self):
        for path in sorted(Path("loaders").glob("*.boot")):
            boot_data = path.read_bytes()
            _, checksum_bytes, size_bytes, payload = libre_gxdl.GXUploader._build_stage2_parts(boot_data)
            checksum = sum(payload) & 0xFFFFFFFF
            self.assertEqual(checksum_bytes, struct.pack("<I", checksum), path.name)
            self.assertEqual(size_bytes, struct.pack("<I", len(boot_data)), path.name)
            self.assertGreater(checksum, 0xFFFF, path.name)

    def test_stage1_uses_vendor_chip_dependent_layouts(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        cases = (
            (0x6612, 0x4000, 0x3FE0),
            (0x6705, 0x2000, 0x1FFC),
            (0x1234, 0x1000, 0x0FFC),
        )

        for chip_id, transfer_size, payload_size in cases:
            boot_data = bytearray(0x5000)
            boot_data[:4] = b"toob"
            boot_data[6:8] = struct.pack("<H", chip_id)
            header, payload, marker = uploader._build_stage1_parts(bytes(boot_data))
            self.assertEqual(header, struct.pack("<BHH", 0x59, transfer_size >> 2, 0))
            self.assertEqual(len(payload), payload_size)
            self.assertEqual(marker, b"boot")

    def test_transfer_mode_flag_is_parsed(self):
        parser = libre_gxdl.build_argument_parser()
        args = parser.parse_args(["-b", "boot.bin", "-d", "/dev/ttyUSB0", "-t", "nns"])
        self.assertEqual(args.transfer_mode, "nns")

    def test_yes_flag_is_parsed(self):
        parser = libre_gxdl.build_argument_parser()
        args = parser.parse_args(["-b", "boot.bin", "-d", "/dev/ttyUSB0", "-y"])
        self.assertTrue(args.yes)

    def test_parse_int_accepts_hex(self):
        self.assertEqual(libre_gxdl.parse_int("0x400000"), 4194304)
        self.assertEqual(libre_gxdl.parse_int("4194304"), 4194304)

    def test_next_ipv4_increments_last_octet(self):
        self.assertEqual(libre_gxdl.next_ipv4("192.168.1.45"), "192.168.1.46")

    def test_tftp_server_receives_wrq(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            payload = b"A" * 600
            server = libre_gxdl.TftpServer(port=20000, timeout=2.0)
            server.start_receive(str(dest))
            time.sleep(0.1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(2.0)
                sock.sendto(struct.pack("!H", 2) + b"out.bin\x00octet\x00", ("127.0.0.1", 20000))
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 0))
                sock.sendto(struct.pack("!HH", 3, 1) + payload[:512], addr)
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 1))
                sock.sendto(struct.pack("!HH", 3, 2) + payload[512:], addr)
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 2))
                self.assertTrue(server.wait(2.0))
            finally:
                sock.close()
                server.stop()
            self.assertEqual(dest.read_bytes(), payload)

    def test_tftp_server_stops_on_exact_blksize_multiple(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            payload = b"B" * 2048
            server = libre_gxdl.TftpServer(port=20001, timeout=2.0)
            server.start_receive(str(dest), expected_size=len(payload))
            time.sleep(0.1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(2.0)
                sock.sendto(
                    struct.pack("!H", 2) + b"out.bin\x00octet\x00blksize\x001024\x00",
                    ("127.0.0.1", 20001),
                )
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 0))
                sock.sendto(struct.pack("!HH", 3, 1) + payload[:1024], addr)
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 1))
                sock.sendto(struct.pack("!HH", 3, 2) + payload[1024:], addr)
                ack, addr = sock.recvfrom(32)
                self.assertEqual(ack, struct.pack("!HH", 4, 2))
                self.assertTrue(server.wait(2.0))
            finally:
                sock.close()
                server.stop()
            self.assertEqual(dest.read_bytes(), payload)
            self.assertIsNone(server.error)

    def test_tftp_server_sends_rrq(self):
        payload = b"C" * 2048
        server = libre_gxdl.TftpServer(port=20002, timeout=2.0)
        server.start_send("out.bin", payload)
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        received = bytearray()
        try:
            sock.settimeout(2.0)
            sock.sendto(
                struct.pack("!H", 1) + b"out.bin\x00octet\x00blksize\x001024\x00",
                ("127.0.0.1", 20002),
            )
            oack, addr = sock.recvfrom(64)
            self.assertEqual(oack[:2], struct.pack("!H", 6))
            sock.sendto(struct.pack("!HH", 4, 0), addr)
            for block in (1, 2):
                packet, addr = sock.recvfrom(4 + 1024)
                opcode, got = struct.unpack("!HH", packet[:4])
                self.assertEqual(opcode, 3)
                self.assertEqual(got, block)
                received.extend(packet[4:])
                sock.sendto(struct.pack("!HH", 4, block), addr)
            try:
                empty, addr = sock.recvfrom(4 + 1024)
                if len(empty) >= 4 and struct.unpack("!HH", empty[:4]) == (3, 3):
                    sock.sendto(struct.pack("!HH", 4, 3), addr)
            except socket.timeout:
                pass
            self.assertTrue(server.wait(2.0))
        finally:
            sock.close()
            server.stop()
        self.assertEqual(bytes(received), payload)
        self.assertIsNone(server.error)

    def test_resolve_boot_file_finds_repository_loader(self):
        resolved = Path(libre_gxdl.resolve_boot_file("gemini-6702H5-sflash-24M.boot"))
        self.assertTrue(resolved.exists())
        self.assertEqual(resolved.name, "gemini-6702H5-sflash-24M.boot")
        loaders = libre_gxdl.packaged_loaders_dir()
        self.assertTrue(loaders.is_dir())
        self.assertTrue(any(loaders.glob("*.boot")))

    def test_load_conf_down_dispatches_to_text_command(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        uploader.upload = Mock(return_value=True)
        uploader.open = Mock(side_effect=lambda: setattr(uploader, "ser", self._fake_serial()))
        uploader.wait_for_prompt = Mock(return_value=True)
        uploader.text_command = Mock(return_value="ok")
        uploader.run_config_commands = Mock(return_value=True)

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("serialdown BOOT boot.bin\n")
            config_path = handle.name

        try:
            result = uploader.run_command_mode(
                "boot.bin",
                "load_conf_down",
                [config_path, "serialdown"],
                transfer_mode="s",
            )
        finally:
            import os
            os.unlink(config_path)

        self.assertTrue(result)
        uploader.run_config_commands.assert_called_once_with(config_path, "serialdown", None)

    def test_nns_transfer_mode_skips_upload_when_prompt_is_available(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        uploader.upload = Mock(return_value=True)
        uploader.open = Mock(side_effect=lambda: setattr(uploader, "ser", self._fake_serial()))
        uploader.wait_for_prompt = Mock(return_value=True)
        uploader.text_command = Mock(return_value="ok")
        uploader.serial_dump = Mock(return_value=True)

        result = uploader.run_command_mode(
            "boot.bin",
            "serialdump",
            ["BOOT", "64", "out.bin"],
            transfer_mode="nns",
        )

        self.assertTrue(result)
        uploader.upload.assert_not_called()

    def test_flash_erase_prompts_but_serial_download_does_not(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        uploader.ser = self._fake_serial()
        uploader.confirm_action = Mock(return_value=True)
        uploader.wait_for_prompt = Mock(return_value=True)
        uploader.text_command = Mock(return_value="ok")

        uploader.flash_erase("BOOT")
        self.assertTrue(uploader.confirm_action.called)

        uploader.confirm_action.reset_mock()
        uploader.serial_download = Mock(return_value=True)
        with patch("builtins.open", side_effect=Exception("should not reach file read")):
            uploader.serial_download("BOOT", "boot.bin")
        self.assertFalse(uploader.confirm_action.called)

    def test_config_file_entries_are_parsed(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("serialdown BOOT boot.bin\n")
            handle.write("flash erase LOGO\n")
            handle.write("# comment\n")
            path = handle.name

        try:
            commands = uploader.parse_config_file(path)
        finally:
            import os
            os.unlink(path)

        self.assertEqual(commands, [["serialdown", "BOOT", "boot.bin"], ["flash", "erase", "LOGO"]])

    def test_sflash_otp_lock_and_setregion_match_vendor_strings(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        uploader.ser = self._fake_serial()
        uploader.confirm_action = Mock(return_value=True)
        uploader.wait_for_prompt = Mock(return_value=True)
        uploader.text_command = Mock(return_value="ok")

        self.assertTrue(uploader.sflash_otp_lock())
        uploader.text_command.assert_called_with("sflash_otp lock", timeout=30.0)

        uploader.text_command.reset_mock()
        self.assertTrue(uploader.sflash_otp_setregion("1"))
        uploader.text_command.assert_called_with("sflash_otp setregion 1", timeout=30.0)

    def test_flash_scrub_and_mark_bad_match_vendor_strings(self):
        uploader = libre_gxdl.GXUploader("/dev/ttyUSB0")
        uploader.ser = self._fake_serial()
        uploader.confirm_action = Mock(return_value=True)
        uploader.wait_for_prompt = Mock(return_value=True)
        uploader.text_command = Mock(return_value="ok")

        self.assertTrue(uploader.flash_scrub())
        uploader.text_command.assert_called_with("flash scrub all", timeout=300.0)

        uploader.text_command.reset_mock()
        self.assertTrue(uploader.flash_scrub("0x0", "0x20000"))
        uploader.text_command.assert_called_with("flash scrub 0x0 0x20000", timeout=120.0)

        uploader.text_command.reset_mock()
        self.assertTrue(uploader.flash_mark_bad("0x20000"))
        uploader.text_command.assert_called_with("flash mark bad 0x20000", timeout=30.0)

    def test_normalize_serial_device_windows_com_prefix(self):
        with patch.object(libre_gxdl.os, "name", "nt"), patch.object(libre_gxdl.sys, "platform", "win32"):
            self.assertEqual(libre_gxdl.normalize_serial_device("COM3"), r"\\.\COM3")
            self.assertEqual(libre_gxdl.normalize_serial_device("com3"), r"\\.\COM3")
            self.assertEqual(libre_gxdl.normalize_serial_device("COM3:"), r"\\.\COM3")
            self.assertEqual(libre_gxdl.normalize_serial_device(r"\\.\COM3"), r"\\.\COM3")
            self.assertEqual(libre_gxdl.normalize_serial_device("3"), r"\\.\COM3")
            self.assertEqual(libre_gxdl.normalize_serial_device("COM10"), r"\\.\COM10")
            self.assertEqual(libre_gxdl.GXUploader("COM3").device, r"\\.\COM3")
        with patch.object(libre_gxdl.os, "name", "posix"), patch.object(libre_gxdl.sys, "platform", "linux"):
            self.assertEqual(libre_gxdl.normalize_serial_device("/dev/ttyUSB0"), "/dev/ttyUSB0")
            self.assertEqual(libre_gxdl.normalize_serial_device("COM3"), "COM3")
        with patch.object(libre_gxdl.os, "name", "posix"), patch.object(libre_gxdl.sys, "platform", "cygwin"):
            self.assertEqual(libre_gxdl.normalize_serial_device("COM3"), "/dev/ttyS2")
        with patch.object(libre_gxdl.os, "name", "posix"), patch.object(libre_gxdl.sys, "platform", "msys"):
            self.assertEqual(libre_gxdl.normalize_serial_device("COM3"), "//./COM3")


if __name__ == "__main__":
    unittest.main()
