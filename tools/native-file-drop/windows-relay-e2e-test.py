"""End to end on one Windows machine: the real host (cursorway-server) -> cursorway-relay -> a real receiver core.

All links use pinned mutual TLS. The receiver runs with CURSORWAY_TEST_NO_POINTER so it does not move
the one pointer the host also watches. The host enters the receiver with a hotkey and leaves it over
the edge with real (injected) pointer motion.

Checks: text and a >1 MB file with a Chinese name reach the receiver, also when the host grabs the
clipboard again while the file is on its way (it used to cancel the transfer); the pointer returns to
the host over the edge; a left button held while the relay restarts does not leave the host stuck;
one host connection until the relay is restarted on purpose."""
import ctypes
import hashlib
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes

binary = pathlib.Path(sys.argv[1]).resolve()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
def report(kind, value, trace):
    import traceback
    print("::error title=Relay end to end::" + "%0A".join("".join(traceback.format_exception(kind, value, trace)).splitlines()[-12:]), flush=True)
    sys.__excepthook__(kind, value, trace)
sys.excepthook = report
user32 = ctypes.WinDLL("user32", use_last_error=True); kernel32 = ctypes.WinDLL("kernel32", use_last_error=True); shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32.GetClipboardData.restype = wintypes.HANDLE; user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
kernel32.GlobalAlloc.restype = wintypes.HGLOBAL; kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]; kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]


def wait(check, what, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value: return value
        time.sleep(.05)
    raise AssertionError(what)


def put_clipboard(fmt, data):
    wait(lambda: user32.OpenClipboard(None), "cannot open the clipboard", 5)
    try:
        handle = kernel32.GlobalAlloc(2, len(data)); pointer = kernel32.GlobalLock(handle)
        ctypes.memmove(pointer, data, len(data)); kernel32.GlobalUnlock(handle); user32.EmptyClipboard()
        assert user32.SetClipboardData(fmt, handle), "SetClipboardData failed"
    finally: user32.CloseClipboard()


def put_text(text): put_clipboard(13, (text + "\0").encode("utf-16-le"))
def put_files(paths): put_clipboard(15, struct.pack("<IiiII", 20, 0, 0, 0, 1) + ("\0".join(map(str, paths)) + "\0\0").encode("utf-16-le"))


def clipboard_files():
    if not user32.OpenClipboard(None): return None
    try:
        handle = user32.GetClipboardData(15)
        if not handle: return None
        count = shell32.DragQueryFileW(handle, 0xFFFFFFFF, None, 0); result = []
        for i in range(count):
            buffer = ctypes.create_unicode_buffer(32768); shell32.DragQueryFileW(handle, i, buffer, 32768); result.append(pathlib.Path(buffer.value))
        return result
    finally: user32.CloseClipboard()


def keys(*codes):
    for c in codes: user32.keybd_event(c, 0, 0, 0)
    for c in reversed(codes): user32.keybd_event(c, 0, 2, 0)


def move(dx, dy, times=1):
    for _ in range(times): user32.mouse_event(0x0001, dx, dy, 0, 0); time.sleep(.01)


with tempfile.TemporaryDirectory(prefix="cursorway-e2e-") as temporary:
    root = pathlib.Path(temporary); processes = []
    logs = {name: root / (name + ".log") for name in ("server", "relay", "user")}
    def text(name): return logs[name].read_text(encoding="utf-8", errors="replace") if logs[name].exists() else ""
    try:
        def pair(*args): return subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, args)], text=True).strip()
        profiles = {name: root / name for name in ("主控", "relay", "user", "system")}
        fp = {name: pair("init", path) for name, path in profiles.items()}
        pair("trust", profiles["主控"], "client", fp["relay"])
        pair("trust", profiles["relay"], "server", fp["主控"])
        pair("trust", profiles["user"], "server", fp["relay"])
        config = root / "server.conf"
        config.write_text("""section: screens
 windows-host:
 windows:
end
section: links
 windows-host:
  right = windows
 windows:
  left = windows-host
end
section: options
 clipboardSharing = true
 keystroke(Control+Alt+Shift+F11) = switchToScreen(windows)
end
""", encoding="utf-8")
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0)); host_port = free.getsockname()[1]
        server = subprocess.Popen([str(binary / "cursorway-server.exe"), "-f", "--no-tray", "--name", "windows-host", "--file-clipboard",
            "--debug", "DEBUG1", "--profile-dir", str(profiles["主控"]), "-c", str(config), "--address", "127.0.0.1:%d" % host_port,
            "--log", str(logs["server"])], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        processes.append(server)
        wait(lambda: "started server" in text("server"), "the host did not start")

        def start_relay(listen):
            relay = subprocess.Popen([str(binary / "cursorway-relay.exe"), "--profile", str(profiles["relay"]), "--host", "127.0.0.1:%d" % host_port,
                "--listen", str(listen), "--user-core", fp["user"], "--system-core", fp["system"], "--name", "windows", "--log", str(logs["relay"])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
            processes.append(relay)
            first = relay.stdout.readline().strip(); assert first.startswith("listening on 127.0.0.1:"), first
            import threading; threading.Thread(target=lambda: [None for _ in relay.stdout], daemon=True).start()
            return relay, int(first.rsplit(":", 1)[1])
        relay, relay_port = start_relay(0)
        environment = dict(os.environ, CURSORWAY_TEST_NO_POINTER="1", CURSORWAY_TEST_SHARED_CLIPBOARD="1")
        user = subprocess.Popen([str(binary / "cursorway-client.exe"), "-f", "--no-tray", "--debug", "DEBUG1", "--profile-dir", str(profiles["user"]),
            "--log", str(logs["user"]), "--name", "windows", "--file-clipboard", "127.0.0.1:%d" % relay_port],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=environment)
        processes.append(user)
        wait(lambda: 'client "windows" has connected' in text("server"), "the relay did not connect to the host", 20)
        wait(lambda: "user core ready" in text("relay"), "the user core did not get ready", 20)
        wait(lambda: text("user").count("file clipboard: peer ready") >= 1, "the receiver did not agree on file clipboard with the host", 20)

        width, height = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        def switches(to): return text("server").count('to "%s"' % to)
        def enter():
            before = switches("windows"); user32.SetCursorPos(width // 2, height // 2); time.sleep(.2)
            keys(0x11, 0x12, 0x10, 0x7A)  # Ctrl+Alt+Shift+F11
            wait(lambda: switches("windows") > before, "the hotkey did not take the input to the receiver")
        def leave_over_edge(what):
            before = switches("windows-host")
            deadline = time.monotonic() + 15
            while switches("windows-host") == before:
                assert time.monotonic() < deadline, what + ":\n" + text("server")[-3000:]
                move(-40, 0, 10); time.sleep(.1)
        def back_again():
            before = switches("windows-host"); user32.SetCursorPos(width // 2, height // 2); time.sleep(.2)
            leave_over_edge("the pointer did not come back to the host over the edge")

        # One machine, one clipboard: the receiver sees every copy too and offers it to the host. Its offers carry
        # the sequence number of its last entry; one trip there and back makes them older than the host's own.
        def host_grabs(): return text("server").count('screen "windows-host" grabbed clipboard 0')
        def copy_on_host(put, value):
            before = host_grabs(); put(value)
            wait(lambda: host_grabs() > before, "the host did not take the copy as its own:\n" + text("server")[-2000:])
            time.sleep(.3)
        enter(); leave_over_edge("the pointer did not come back to the host over the edge (warm-up)")
        # 1. Text from the host reaches the receiver.
        updates = text("user").count("clipboard was updated")
        copy_on_host(put_text, "Cursorway 端到端 %d" % time.time_ns())
        enter()
        wait(lambda: text("user").count("clipboard was updated") > updates, "the receiver did not get the host's text")
        leave_over_edge("the pointer did not come back to the host over the edge")

        # 2. A file; the host grabs the clipboard again just after the transfer starts (it used to cancel it).
        payload = os.urandom(1 << 20) + hashlib.sha256(b"cursorway").digest() * 4000
        source = root / "來源" / "主控端的檔案 測試.bin"; source.parent.mkdir(); source.write_bytes(payload)
        verified = text("user").count("file clipboard: received and verified")
        copy_on_host(put_files, [source])
        enter()
        wait(lambda: "file clipboard: sending" in text("server")[-20000:], "the host did not start sending the file")
        put_files([source])
        wait(lambda: text("user").count("file clipboard: received and verified") > verified,
             "the file did not reach the receiver:\n" + text("server")[-2000:] + "\n" + text("user")[-2000:], 30)
        files = wait(lambda: (lambda f: f if f and f[0] != source else None)(clipboard_files()), "the receiver did not put the received file on the clipboard")
        assert files[0].name == source.name, files
        assert hashlib.sha256(files[0].read_bytes()).digest() == hashlib.sha256(payload).digest(), "the received file differs"
        leave_over_edge("the pointer did not come back to the host after the file")

        # 3. One host connection so far.
        assert text("server").count('client "windows" has connected') == 1, "the relay connected to the host more than once"

        # 4. Left button held on the receiver while the relay restarts: the host must not stay stuck.
        enter(); user32.mouse_event(0x0002, 0, 0, 0, 0); time.sleep(.3)
        relay.kill(); relay.wait()
        wait(lambda: 'client "windows" has disconnected' in text("server"), "the host did not notice the relay going away")
        relay, _ = start_relay(relay_port)
        wait(lambda: text("server").count('client "windows" has connected') >= 2, "the relay did not reconnect to the host", 30)
        time.sleep(1); user32.mouse_event(0x0004, 0, 0, 0, 0); time.sleep(.5)
        if text("server").rfind('to "windows"') > text("server").rfind('to "windows-host"'):
            leave_over_edge("after the restart with the button held, the pointer could not leave the receiver")
        enter(); back_again()
        print("::notice title=Relay end to end::text and a %d byte file reached the receiver through the relay (with a second grab mid-transfer); edge return and a relay restart with the button held work" % len(payload))
        print("PASS: real host -> relay -> receiver core")
    except Exception:
        for name, path in logs.items():
            if path.exists(): print("==", name); print(path.read_text(encoding="utf-8", errors="replace")[-5000:]); print("::error title=" + str(name) + "::" + "%0A".join(path.read_text(encoding="utf-8", errors="replace")[-2500:].replace("%", "%25").splitlines()), flush=True)
        raise
    finally:
        for p in processes:
            if p.poll() is None: p.kill()
        for p in processes: p.wait()
