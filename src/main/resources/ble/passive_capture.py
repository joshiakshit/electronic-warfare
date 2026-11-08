"""Linux-only passive BLE receiver. Standard-library Python; stdout is BTSnoop H4.

Never resets/powers the controller, requests scan responses, pairs, or connects.
An already enabled scan is not disabled to make room for this session.
"""
import argparse
import fcntl
import os
import signal
import socket
import struct
import sys
import time

EPOCH_OFFSET = 0x00DCDDB30F2F8000
stopping = False


class StopRequested(Exception):
    pass


class HciError(RuntimeError):
    def __init__(self, opcode, status):
        self.status = status
        reason = {
            0x01: "unsupported command",
            0x0C: "command disallowed; stop other BLE discovery/monitoring sessions first",
            0x11: "unsupported controller feature",
        }.get(status, "controller rejected the command")
        super().__init__(f"HCI 0x{opcode:04x} failed (status 0x{status:02x}): {reason}")


# Exact HCI parameter allowlist at the socket boundary. In both parameter
# commands the scan type is fixed to zero, even if a future caller changes.
PASSIVE_COMMANDS = {
    0x2041: (struct.pack("<BBBBHH", 0, 0, 1, 0, 0x20, 0x10),),
    0x2042: (struct.pack("<BBHH", 1, 0, 0, 0), bytes(6)),
    0x200B: (struct.pack("<BHHBB", 0, 0x20, 0x10, 0, 0),),
    0x200C: (b"\x01\x00", bytes(2)),
}


def command(sock, opcode, parameters):
    if parameters not in PASSIVE_COMMANDS.get(opcode, ()):
        raise RuntimeError("HCI command is outside the passive scan allowlist")
    sock.sendall(b"\x01" + struct.pack("<HB", opcode, len(parameters)) + parameters)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            packet = sock.recv(4096)
        except socket.timeout:
            continue
        if len(packet) < 7 or packet[0] != 4:
            continue
        if packet[1] == 0x0E and struct.unpack_from("<H", packet, 4)[0] == opcode:
            status = packet[6]
        elif packet[1] == 0x0F and struct.unpack_from("<H", packet, 5)[0] == opcode:
            status = packet[3]
        else:
            continue
        if status:
            raise HciError(opcode, status)
        return
    raise RuntimeError("Bluetooth command timed out; check that the adapter is powered and available")


def configure_passive_scan(send):
    # Scan type 0 is passive. Listen for 10 ms out of each 20 ms interval.
    # Prefer extended reports on 1M PHY; do not change the global LE event mask.
    if stopping:
        raise StopRequested()
    try:
        send(0x2041, struct.pack("<BBBBHH", 0, 0, 1, 0, 0x20, 0x10))
    except HciError as error:
        if error.status not in (0x01, 0x0C, 0x11):
            raise
        if stopping:
            raise StopRequested()
        # An enabled scan also rejects legacy parameters; no forced disable.
        send(0x200B, struct.pack("<BHHBB", 0, 0x20, 0x10, 0, 0))
        if stopping:
            raise StopRequested()
        send(0x200C, b"\x01\x00")
        return 0x200C, b"\x00\x00"
    if stopping:
        raise StopRequested()
    send(0x2042, struct.pack("<BBHH", 1, 0, 0, 0))
    return 0x2042, bytes(6)


def capture(index, output):
    global stopping
    # Only one ewave session may own scan setup for an adapter. Other BlueZ
    # applications must not start/alter discovery during this session.
    lock_path = f"/run/lock/ewave-ble-hci{index}.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"Another ewave BLE session is using hci{index}") from None
        with socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI) as sock:
            sock.bind((index, 0))
            sock.settimeout(0.2)
            # H4 events only: command complete/status and LE Meta. No ACL/key data.
            event_mask = (1 << 0x0E) | (1 << 0x0F)
            sock.setsockopt(0, 2, struct.pack("<IIIHH", 1 << 4, event_mask, 1 << (0x3E - 32), 0, 0))
            disable = None
            try:
                disable = configure_passive_scan(lambda opcode, params: command(sock, opcode, params))
                print(f"Passive BLE scan started on hci{index}; no scan requests or connections", file=sys.stderr, flush=True)
                output.write(b"btsnoop\0" + struct.pack(">II", 1, 1002))
                output.flush()
                while not stopping:
                    try:
                        packet = sock.recv(4096)
                    except socket.timeout:
                        continue
                    if len(packet) < 5 or packet[0:2] != b"\x04\x3e" or packet[3] not in (0x02, 0x0D):
                        continue
                    timestamp = time.time_ns() // 1000 + EPOCH_OFFSET
                    output.write(struct.pack(">IIIIQ", len(packet), len(packet), 3, 0, timestamp))
                    output.write(packet)
                    output.flush()
            finally:
                if disable is not None:
                    try:
                        command(sock, *disable)
                        print(f"ewave passive BLE scan stopped on hci{index}", file=sys.stderr, flush=True)
                    except (OSError, RuntimeError) as error:
                        print(f"Could not stop the owned BLE scan: {error}", file=sys.stderr, flush=True)
    finally:
        os.close(lock_fd)


def main():
    global stopping
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.index <= 65535:
        parser.error("adapter index must be in 0..65535")

    def stop(_signum, _frame):
        global stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        capture(args.index, sys.stdout.buffer)
    except StopRequested:
        return 0
    except (OSError, RuntimeError) as error:
        print(f"BLE capture failed on hci{args.index}: {error}. Use a powered adapter and capture permissions (sudo).", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
