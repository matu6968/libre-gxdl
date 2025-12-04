import serial
import threading
import time
import os
from datetime import datetime

# ---- CONFIG ----
TX_PORT = "/dev/ttyUSB1"   # device TX -> your RX
RX_PORT = "/dev/ttyUSB2"   # device RX -> your RX
BAUD = 115200

PACKET_GAP = 0.5  # seconds of silence defines packet boundary
OUTPUT_DIR = "packets"
# -----------------

os.makedirs(OUTPUT_DIR, exist_ok=True)

sent_counter = 0
recv_counter = 0
lock = threading.Lock()


def save_packet(data: bytes, direction: str):
    """Save a packet as a hex text file with timestamp."""
    global sent_counter, recv_counter

    hexstr = " ".join(f"{b:02X}" for b in data)
    timestamp = datetime.now()

    with lock:
        if direction == "sent":
            sent_counter += 1
            filename = os.path.join(OUTPUT_DIR, f"sent_{sent_counter:06}.txt")
        else:
            recv_counter += 1
            filename = os.path.join(OUTPUT_DIR, f"recv_{recv_counter:06}.txt")

    with open(filename, "w") as f:
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Direction: {direction}\n")
        f.write(f"Length: {len(data)} bytes\n\n")
        f.write(hexstr + "\n")

    print(f"[+] Saved {direction} packet ({len(data)} bytes) → {filename}")


def serial_reader(port: str, direction: str):
    ser = serial.Serial(port, BAUD, timeout=0)
    packet = bytearray()
    last_byte_time = time.time()

    print(f"[*] Listening on {port} ({direction})")

    while True:
        b = ser.read(32768)


        if b:
            packet.extend(b)
            last_byte_time = time.time()
        else:
            if packet and (time.time() - last_byte_time) > PACKET_GAP:
                save_packet(bytes(packet), direction)
                packet.clear()

        time.sleep(0.001)  # avoid busy loop


def main():
    t1 = threading.Thread(target=serial_reader, args=(TX_PORT, "sent"), daemon=True)
    t2 = threading.Thread(target=serial_reader, args=(RX_PORT, "recv"), daemon=True)

    t1.start()
    t2.start()

    print("[*] Sniffer running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting.")


if __name__ == "__main__":
    main()
