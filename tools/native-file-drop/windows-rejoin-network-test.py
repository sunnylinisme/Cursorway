"""Production server over mutual TLS: the cursor goes to a receiver, the receiver's connection
drops (as when the Windows service replaces the core on a desktop switch) and the same receiver
connects again; the host must put the cursor back on it ("is back, returning the cursor").

The receiver is simulated here: a real receiver core on the same desktop as the host moves the
same pointer the host is watching, and the two fight over it. The real receiver's quick retries
are covered by the service and clipboard tests."""
import ctypes
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
def report(kind, value, trace):
    # Anything that ends the test early still leaves an annotation (job logs need a token to read).
    import traceback
    print("::error title=Rejoin crash::" + "%0A".join("".join(traceback.format_exception(kind, value, trace)).splitlines()[-12:]), flush=True)
    sys.__excepthook__(kind, value, trace)
sys.excepthook = report
user32 = ctypes.windll.user32
processes = []


class Receiver:
    """A simulated receiver: handshake, screen info, keep-alives; records what the host sends."""
    def __init__(self, port, context):
        peer = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.wire = context.wrap_socket(peer, server_hostname="Barrier"); self.wire.settimeout(10)
        assert self.receive().startswith(b"Barrier")
        self.send(b"Barrier" + struct.pack("!HHI", 1, 6, 7) + b"windows")
        while True:
            message = self.receive()
            if message == b"QINF": self.send(b"DINF" + struct.pack("!hhhhhhh", 0, 0, 1024, 768, 0, 512, 384))
            if message.startswith(b"EBSY"): raise RuntimeError("host says the name is in use")
            if message.startswith(b"DSOP"): break
        self.send(b"CNDF" + struct.pack("!I", 1))
    def send(self, message): self.wire.sendall(struct.pack("!I", len(message)) + message)
    def exact(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.wire.recv(size - len(data))
            if not part: raise RuntimeError("host disconnected")
            data.extend(part)
        return bytes(data)
    def receive(self):
        size, = struct.unpack("!I", self.exact(4)); assert size < 1 << 20
        message = self.exact(size)
        if message == b"CALV": self.send(b"CALV")
        return message
    def until(self, code, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.wire.settimeout(max(.1, deadline - time.monotonic()))
            try: message = self.receive()
            except socket.timeout: break
            if message.startswith(code): return message
        return None
    def drop(self):
        # As abruptly as a killed core: reset, no goodbye.
        self.wire.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); self.wire.close()


with tempfile.TemporaryDirectory(prefix="cursorway-rejoin-") as temporary:
    root = pathlib.Path(temporary)
    console = open(root / "console.log", "w", encoding="utf-8")
    server_log = root / "server.log"
    def read(path): return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    try:
        def pair(*args): return subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, args)], text=True).strip()
        host, receiver = root / "host", root / "receiver"
        pair("init", host); receiver_fp = pair("init", receiver)
        pair("trust", host, "client", receiver_fp)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED; context.verify_flags = 0
        context.load_cert_chain(receiver / "SSL/Barrier.pem"); context.load_verify_locations(host / "SSL/Barrier.pem")
        config = root / "rejoin.conf"
        config.write_text("section: screens\n windows-host:\n windows:\nend\nsection: links\n windows-host:\n  right = windows\n windows:\n  left = windows-host\nend\n"
                          "section: options\n clipboardSharing = false\nend\n", encoding="utf-8")
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0)); port = free.getsockname()[1]
        processes.append(subprocess.Popen([str(binary / "cursorway-server.exe"), "-f", "--no-tray", "--name", "windows-host", "--debug", "INFO",
            "--profile-dir", str(host), "-c", str(config), "--address", "127.0.0.1:" + str(port), "--log", str(server_log)], stdout=console, stderr=subprocess.STDOUT))
        deadline = time.monotonic() + 15
        while True:
            try: first = Receiver(port, context); break
            except OSError:
                if time.monotonic() > deadline or processes[0].poll() is not None: raise
                time.sleep(.2)
        # Push the pointer through the right edge until the host hands the cursor to the receiver.
        width = user32.GetSystemMetrics(0); entered = None
        for _ in range(40):
            user32.SetCursorPos(width - 40, 300)
            for _ in range(8): user32.mouse_event(0x0001, 30, 0, 0, 0); time.sleep(.01)
            entered = first.until(b"CINN", .3)
            if entered: break
        assert entered, "host never switched to the receiver"
        # The receiver's core goes away while it has the cursor, and a new one connects.
        first.drop(); dropped = time.monotonic()
        while True:
            try: second = Receiver(port, context); break
            except (OSError, RuntimeError, AssertionError):
                if time.monotonic() - dropped > 8: raise
                time.sleep(.25)
        took = time.monotonic() - dropped
        back = second.until(b"CINN", 5)
        assert back, "host did not return the cursor to the receiver"
        assert 'client "windows" is back, returning the cursor to it' in read(server_log), "host log does not say it returned the cursor"
        busy = read(server_log).count('a client with name "windows" is already connected')
        print("::notice title=Rejoin::receiver connected again %.2f s after the drop (%d busy refusals); cursor returned" % (took, busy))
        # The host replaces the stale connection of the same receiver (same certificate) at once.
        assert busy == 0, "host refused the reconnecting receiver %d times as already connected" % busy
        assert "reconnected, dropping its stale connection" in read(server_log), "host did not say it replaced the stale connection"
        assert took < 2, "reconnecting took %.2f s" % took
        second.drop()
        print("PASS: the receiver's connection dropped while it had the cursor and the host put the cursor back on it (%.2f s)" % took)
    except Exception as failure:
        console.flush()
        lines = [l for l in read(server_log).splitlines() if any(k in l for k in ("switch", "connected", "disconnected", "is back", "jump", "ERROR", "WARN"))]
        print("::error title=Rejoin::%s%%0A%s" % (" ".join(str(failure).splitlines()), "%0A".join(l[-160:] for l in lines[-25:])))
        print(read(server_log)[-6000:])
        raise
    finally:
        for p in processes:
            if p.poll() is None: p.kill()
        for p in processes: p.wait()
        console.close()
