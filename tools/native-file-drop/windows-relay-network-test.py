"""cursorway-relay with a simulated host and two real receiver cores (user and system roles).

The host must see one connection the whole time while the relay switches the input between the
cores, a core is killed and comes back, and the clipboard goes only to the user core. A key held
when the input moves to the other core must not stay pressed."""
import ctypes
import hashlib
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from ctypes import wintypes

binary = pathlib.Path(sys.argv[1]).resolve()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
def report(kind, value, trace):
    import traceback
    print("::error title=Relay::" + "%0A".join("".join(traceback.format_exception(kind, value, trace)).splitlines()[-12:]), flush=True)
    sys.__excepthook__(kind, value, trace)
sys.excepthook = report
user32 = ctypes.WinDLL("user32", use_last_error=True)


def cursor():
    point = wintypes.POINT(); user32.GetPhysicalCursorPos(ctypes.byref(point)); return point.x, point.y


def wait(check, what, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value: return value
        time.sleep(.05)
    raise AssertionError(what)


def windows_clipboard():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetClipboardData.restype = wintypes.HANDLE; kernel32.GlobalLock.restype = ctypes.c_void_p; kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    if not user32.OpenClipboard(None): return None
    try:
        handle = user32.GetClipboardData(13)
        if not handle: return None
        pointer = kernel32.GlobalLock(handle)
        try: return ctypes.wstring_at(pointer)
        finally: kernel32.GlobalUnlock(handle)
    finally: user32.CloseClipboard()


class Host:
    """The simulated host: accepts the relay, answers keep-alives in the background."""
    def __init__(self, connection):
        self.wire = connection; self.wire.settimeout(10); self.lock = threading.Lock(); self.inbox = []; self.alive = True
        self.send(b"Barrier" + struct.pack("!HH", 1, 6))
        hello = self.exact_message(); assert hello.startswith(b"Barrier"), hello
        self.send(b"QINF")
        threading.Thread(target=self.reader, daemon=True).start()
        threading.Thread(target=self.keepalive, daemon=True).start()
    def send(self, message):
        with self.lock: self.wire.sendall(struct.pack("!I", len(message)) + message)
    def exact(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.wire.recv(size - len(data))
            if not part: raise RuntimeError("relay disconnected from the host")
            data.extend(part)
        return bytes(data)
    def exact_message(self):
        size, = struct.unpack("!I", self.exact(4)); return self.exact(size)
    def reader(self):
        try:
            while self.alive:
                message = self.exact_message()
                if message == b"CALV": continue
                self.inbox.append(message)
        except Exception as error:
            if self.alive: self.inbox.append(b"DROPPED " + str(error).encode())
    def keepalive(self):
        while self.alive:
            try: self.send(b"CALV")
            except Exception: return
            time.sleep(1)
    def until(self, code, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for i, m in enumerate(self.inbox):
                assert not m.startswith(b"DROPPED"), m
                if m.startswith(code): del self.inbox[i]; return m
            time.sleep(.02)
        raise AssertionError("host did not get " + code.decode())


with tempfile.TemporaryDirectory(prefix="cursorway-relay-") as temporary:
    root = pathlib.Path(temporary); processes = []
    try:
        def pair(*args): return subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, args)], text=True).strip()
        profiles = {name: root / name for name in ("host", "relay", "user", "system")}
        fp = {name: pair("init", path) for name, path in profiles.items()}
        pair("trust", profiles["relay"], "server", fp["host"])
        for core in ("user", "system"): pair("trust", profiles[core], "server", fp["relay"])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.verify_mode = ssl.CERT_REQUIRED; context.verify_flags = 0
        context.load_cert_chain(profiles["host"] / "SSL/Barrier.pem"); context.load_verify_locations(profiles["relay"] / "SSL/Barrier.pem")
        listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(4); listener.settimeout(30)
        host_port = listener.getsockname()[1]
        relay_log = root / "relay.log"
        relay = subprocess.Popen([str(binary / "cursorway-relay.exe"), "--profile", str(profiles["relay"]), "--host", "127.0.0.1:%d" % host_port, "--listen", "0",
                                  "--user-core", fp["user"], "--system-core", fp["system"], "--name", "windows", "--log", str(relay_log)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
        processes.append(relay)
        first = relay.stdout.readline().strip(); assert first.startswith("listening on 127.0.0.1:"), first
        relay_port = int(first.rsplit(":", 1)[1])
        threading.Thread(target=lambda: [None for _ in relay.stdout], daemon=True).start()
        def route(to): relay.stdin.write("ROUTE " + to + "\n"); relay.stdin.flush()
        def core(name, clipboard):
            log = root / (name + ".log")
            args = [str(binary / "cursorway-client.exe"), "-f", "--no-tray", "--debug", "DEBUG", "--profile-dir", str(profiles[name]), "--log", str(log), "--name", "windows"]
            if clipboard: args.append("--file-clipboard")
            p = subprocess.Popen(args + ["127.0.0.1:%d" % relay_port], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT); processes.append(p); return p, log
        def log_text(path): return path.read_text(errors="replace") if path.exists() else ""
        user, user_log = core("user", True)
        system, system_log = core("system", False)
        peer, _ = listener.accept(); listener.settimeout(1)
        host = Host(context.wrap_socket(peer, server_side=True))
        assert hashlib.sha256(host.wire.getpeercert(binary_form=True)).hexdigest() == fp["relay"].split(":", 2)[2], "relay showed another identity"
        info = host.until(b"DINF"); host.send(b"CIAK"); host.send(b"CROP")
        # The host must see the user desktop's real shape, or it cannot tell when the pointer leaves an edge.
        shape = struct.unpack("!hhhh", info[4:12]); metrics = tuple(user32.GetSystemMetrics(i) for i in (76, 77, 78, 79))
        assert shape == metrics, "the host was given the shape %r, the desktop is %r" % (shape, metrics)
        host.send(b"DSOP" + struct.pack("!I", 2) + b"CLPS" + struct.pack("!I", 1))
        assert host.until(b"FCAP") == b"FCAP" + struct.pack("!I", 2), "the user core's file clipboard did not reach the host"
        host.send(b"FCAP" + struct.pack("!I", 2))
        wait(lambda: "ready" in log_text(relay_log) and log_text(relay_log).count(" ready") >= 2, "both cores did not get ready", 15)
        # 1. The user core has the input.
        host.send(b"CINN" + struct.pack("!hhIH", 60, 60, 1, 0))
        host.send(b"DMMV" + struct.pack("!hh", 120, 130)); wait(lambda: abs(cursor()[0] - 120) <= 1 and abs(cursor()[1] - 130) <= 1, "the user core did not move the pointer")
        wait(lambda: "entering screen" in log_text(user_log), "the user core was not entered")
        assert "entering screen" not in log_text(system_log), "the system core got input while the user desktop was active"
        # 2. Text from the host reaches the Windows clipboard through the user core only.
        text = "Cursorway relay ✓"; data = text.encode(); blob = struct.pack("!III", 1, 0, len(data)) + data
        def string(value): return struct.pack("!I", len(value)) + value
        for mark, body in ((1, str(len(blob)).encode()), (2, blob), (3, b"")): host.send(b"DCLP" + struct.pack("!BIB", 0, 7, mark) + string(body))
        time.sleep(1); wait(lambda: windows_clipboard() == text, "text from the host did not reach the clipboard", 5)
        assert "clipboard was updated" not in log_text(system_log), "the system core got the clipboard"
        # 2b. A large transfer while the pointer keeps moving: the relay's writes to the core back up and are
        # retried with a grown buffer; the connections must stay (a file drag dropped the host link in 0.3.34).
        big = ("Cursorway " * 300000).encode(); blob = struct.pack("!III", 1, 0, len(big)) + big
        for mark, body in ((1, str(len(blob)).encode()), (2, blob), (3, b"")):
            host.send(b"DCLP" + struct.pack("!BIB", 0, 8, mark) + string(body))
            for i in range(50): host.send(b"DMMV" + struct.pack("!hh", 100 + i, 100))
        host.send(b"DMMV" + struct.pack("!hh", 222, 233)); wait(lambda: abs(cursor()[0] - 222) <= 1 and abs(cursor()[1] - 233) <= 1, "the pointer stopped after a large transfer", 15)
        assert "disconnected" not in log_text(relay_log), log_text(relay_log)
        # 3. Shift held on the host; the input moves to the system core: Shift must not stay down.
        host.send(b"DKDN" + struct.pack("!HHH", 0xEFE1, 0, 42)); time.sleep(.3)
        assert user32.GetAsyncKeyState(0x10) & 0x8000, "the user core did not press Shift"
        started = time.monotonic(); route("system")
        wait(lambda: "entering screen" in log_text(system_log), "the system core was not entered after the switch")
        switched = time.monotonic() - started
        wait(lambda: not user32.GetAsyncKeyState(0x10) & 0x8000, "Shift stayed pressed after the switch", 3)
        host.send(b"DKUP" + struct.pack("!HHH", 0xEFE1, 0, 42))
        host.send(b"DMMV" + struct.pack("!hh", 300, 310)); wait(lambda: abs(cursor()[0] - 300) <= 1 and abs(cursor()[1] - 310) <= 1, "the system core did not move the pointer")
        # 4. The system core dies and comes back; the host connection stays.
        system.kill(); system.wait(); system, system_log2 = core("system", False)
        wait(lambda: log_text(relay_log).count("system core ready") >= 2, "the restarted system core did not get ready", 15)
        host.send(b"DMMV" + struct.pack("!hh", 410, 420)); wait(lambda: abs(cursor()[0] - 410) <= 1 and abs(cursor()[1] - 420) <= 1, "the restarted system core did not get the input")
        # The route goes over the relay's stdin, the input over the network: wait for the switch.
        switches = log_text(relay_log).count("route: user desktop"); route("user")
        wait(lambda: log_text(relay_log).count("route: user desktop") > switches, "the relay did not switch back to the user core")
        host.send(b"DMMV" + struct.pack("!hh", 500, 510)); wait(lambda: abs(cursor()[0] - 500) <= 1 and abs(cursor()[1] - 510) <= 1, "the user core did not get the input back")
        # 5. One connection from the relay the whole time.
        try: listener.accept(); raise AssertionError("the relay connected to the host a second time")
        except socket.timeout: pass
        assert not any(m.startswith(b"DROPPED") for m in host.inbox), host.inbox
        print("::notice title=Relay::input moved to the other core in %.2f s; one host connection throughout" % switched)
        print("PASS: one host connection while the input moved between the cores, a core restarted, the clipboard went only to the user core and no key stayed pressed")
        host.alive = False
    except Exception:
        for path in [root / "relay.log", root / "user.log", root / "system.log"]:
            if path.exists(): print("==", path.name); print(path.read_text(errors="replace")[-4000:])
        raise
    finally:
        for p in processes:
            if p.poll() is None: p.kill()
        for p in processes: p.wait()
