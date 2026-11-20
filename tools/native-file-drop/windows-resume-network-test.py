"""File clipboard resume: a simulated TLS host sends to the real Windows receiver core, drops the
connection halfway through a 50 MB file, reconnects and must only have to send the rest.
Also checks that a cancelled transfer (the app's discard-resume marker) starts from zero."""
import hashlib
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
small = bytes(range(256)) * 4096                     # 1 MiB, finished before the drop
large = bytes(reversed(range(256))) * (200 * 1024)   # 50 MiB, interrupted halfway
CHUNK = 65536
HALF = 400 * CHUNK                                   # 25 MiB sent before the drop


def string(value): return struct.pack("!I", len(value)) + value


class Wire:
    def __init__(self, connection):
        self.connection = connection
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.settimeout(20)

    def send(self, message):
        self.connection.sendall(struct.pack("!I", len(message)) + message)

    def exact(self, count):
        result = bytearray()
        while len(result) < count:
            part = self.connection.recv(count - len(result))
            if not part: raise RuntimeError("Receiver disconnected")
            result.extend(part)
        return bytes(result)

    def receive(self):
        size, = struct.unpack("!I", self.exact(4))
        assert size < 20 * 1024 * 1024
        message = self.exact(size)
        if message == b"CALV": self.send(b"CALV")
        return message

    def until(self, code):
        for _ in range(500):
            message = self.receive()
            if message.startswith(code): return message
            if message[:4] in (b"FCNO", b"FCAB"): raise AssertionError("Transfer rejected: " + repr(message[:300]))
        raise RuntimeError("Missing " + repr(code))


class Transfer:
    """One offer on one connection; every packet must be acknowledged in order."""
    def __init__(self, wire, transfer, key):
        self.wire, self.id, self.counter, self.key = wire, transfer, 0, key

    def packet(self, code, body=b""):
        self.wire.send(code + struct.pack("!I", self.id) + body)
        response = self.wire.until(b"FCAK")
        assert response == b"FCAK" + struct.pack("!II", self.id, self.counter), response[:40]
        self.counter += 1

    def offer(self):
        self.wire.send(b"FCBR" + struct.pack("!IBI", self.id, 0, 42) + string(self.key.encode()))
        reply = self.wire.until(b"FCRS")
        identifier, entries = struct.unpack_from("!II", reply, 4)
        assert identifier == self.id
        offset = 12; length, = struct.unpack_from("!I", reply, offset); listed = reply[offset + 4:offset + 4 + length]
        offset += 4 + length; length, = struct.unpack_from("!I", reply, offset); held = int(reply[offset + 4:offset + 4 + length])
        self.counter = 1
        return entries, listed, held

    def entry(self, name, size):
        self.packet(b"FCEN", b"\x01" + string(name.encode()) + string(str(size).encode()))

    def chunks(self, data, start, stop):
        for offset in range(start, stop, CHUNK):
            self.packet(b"FCHK", string(data[offset:min(stop, offset + CHUNK)]))


def listing(*items):
    digest = hashlib.sha256()
    for name, size in items: digest.update((name + "\n" + str(size) + "\n").encode())
    return digest.digest()


with tempfile.TemporaryDirectory(prefix="cursorway-resume-") as temporary:
    root = pathlib.Path(temporary)
    profile, host_profile = root / "接收設定", root / "主控設定"
    pair = lambda *a: subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, a)], text=True).strip()
    client_fp, host_fp = pair("init", profile), pair("init", host_profile)
    pair("trust", profile, "server", host_fp); pair("trust", host_profile, "client", client_fp)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED; context.verify_flags = 0
    context.load_cert_chain(host_profile / "SSL/Barrier.pem")
    context.load_verify_locations(profile / "SSL/Barrier.pem")
    log = root / "core.log"
    console = open(root / "console.log", "w", encoding="utf-8")
    core = None
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(4); listener.settimeout(40)
            port = listener.getsockname()[1]
            # --harden: the receiver core the service starts with UI access runs hardened; resuming must work there.
            core = subprocess.Popen([str(binary / "cursorway-client.exe"), "-f", "--no-tray", "--debug", "DEBUG1", "--file-clipboard", "--harden",
                                     "--profile-dir", str(profile), "--log", str(log), "--name", "windows", "127.0.0.1:" + str(port)],
                                    stdout=console, stderr=subprocess.STDOUT)

            def connect():
                peer, _ = listener.accept()
                connection = context.wrap_socket(peer, server_side=True)
                wire = Wire(connection)
                wire.send(b"Barrier" + struct.pack("!HH", 1, 6))
                assert wire.until(b"Barrier").endswith(b"windows")
                wire.send(b"QINF"); wire.until(b"DINF")
                wire.send(b"CIAK"); wire.send(b"CROP")
                # Advertise resume; the receiver must answer FCAP 3 (older ones answer 2).
                wire.send(b"DSOP" + struct.pack("!I", 4) + b"CLPS" + struct.pack("!I", 1) + b"FRSM" + struct.pack("!I", 1))
                assert wire.until(b"FCAP") == b"FCAP" + struct.pack("!I", 3), "Receiver did not offer resume"
                wire.send(b"FCAP" + struct.pack("!I", 2))
                return connection, wire

            def resumed_lines(): return [l for l in log.read_text(errors="replace").splitlines() if "resuming at" in l]

            key = hashlib.sha256(b"selection one").hexdigest()
            # 1. First attempt: a whole small file, then half of the large one, then the line drops.
            connection, wire = connect()
            transfer = Transfer(wire, 1001, key)
            assert transfer.offer() == (0, listing(), 0), "Fresh offer reported a resume point"
            transfer.entry("small.bin", len(small)); transfer.chunks(small, 0, len(small))
            transfer.packet(b"FCFE", string(hashlib.sha256(small).digest()))
            transfer.entry("large.bin", len(large)); transfer.chunks(large, 0, HALF)
            connection.close()

            # 2. The receiver reconnects by itself; the same selection resumes after the small file and 25 MiB.
            connection, wire = connect()
            transfer = Transfer(wire, 1002, key)
            entries, listed, held = transfer.offer()
            assert (entries, listed) == (1, listing(("small.bin", len(small)))), (entries, listed)
            assert held == HALF, "Receiver holds %d bytes of the large file, expected %d" % (held, HALF)
            time.sleep(.5)
            assert any("resuming at 1 items, %d bytes" % (len(small) + HALF) in l for l in resumed_lines()), resumed_lines()
            transfer.chunks(large, HALF, len(large))
            transfer.packet(b"FCFE", string(hashlib.sha256(large).digest()))
            transfer.wire.send(b"FCDN" + struct.pack("!I", transfer.id))
            assert transfer.wire.until(b"FCAK") == b"FCAK" + struct.pack("!II", transfer.id, transfer.counter)
            time.sleep(.5)
            assert "received and verified %d bytes" % (len(small) + len(large)) in log.read_text(errors="replace"), "Resumed transfer was not verified"
            assert not (profile / "FileClipboardCache" / "resume" / key).exists(), "Finished transfer left its partial copy"
            received = [p for p in (profile / "FileClipboardCache").rglob("large.bin")]
            assert received and received[0].read_bytes() == large, "Resumed file differs from the original"

            # 3. Cancelled by the user: the app leaves the marker; nothing may resume after that.
            other = hashlib.sha256(b"selection two").hexdigest()
            transfer = Transfer(wire, 1003, other)
            assert transfer.offer()[2] == 0
            transfer.entry("large.bin", len(large)); transfer.chunks(large, 0, 10 * CHUNK)
            (profile / "FileClipboardCache" / "discard-resume").write_text("")
            connection.close()
            connection, wire = connect()
            transfer = Transfer(wire, 1004, other)
            assert transfer.offer() == (0, listing(), 0), "A cancelled transfer resumed"
            assert not (profile / "FileClipboardCache" / "discard-resume").exists(), "Cancel marker was not consumed"

            # 4. A key that could escape the cache folder is refused.
            wire.send(b"FCBR" + struct.pack("!IBI", 1005, 0, 42) + string(b"../" + b"a" * 61))
            assert wire.until(b"FCNO")[:8] == b"FCNO" + struct.pack("!I", 1005)
            connection.close()
            print("PASS: receiver resumed after a dropped connection (1 finished file + 25 MiB kept, only the rest sent, "
                  "SHA-256 verified), a cancelled transfer started over, and an unsafe key was refused")
    finally:
        if core is not None:
            if core.poll() is None: core.terminate()
            core.wait(timeout=10)
        console.close()
        if log.exists(): print(log.read_text(errors="replace")[-15000:])
