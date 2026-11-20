"""Production server + production client over mutual TLS: the cursor goes to the receiver, the
receiver's core is killed and started again at once (as the Windows service does when the input
desktop switches), and the host must put the cursor back on it ("is back, returning the cursor").
It also times how long the new core takes to connect (quick retries after a start)."""
import ctypes
import pathlib
import re
import socket
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
MOUSEEVENTF_MOVE = 0x0001
processes = []
with tempfile.TemporaryDirectory(prefix="cursorway-rejoin-") as temporary:
    root = pathlib.Path(temporary)
    console = open(root / "console.log", "w", encoding="utf-8")
    server_log, client_log = root / "server.log", root / "client.log"
    def read(path): return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    def wait(check, what, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if check(): return
            time.sleep(0.1)
        raise AssertionError(what)
    try:
        def pair(*args): return subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, args)], text=True).strip()
        host, receiver = root / "host", root / "receiver"
        host_fp, receiver_fp = pair("init", host), pair("init", receiver)
        pair("trust", host, "client", receiver_fp); pair("trust", receiver, "server", host_fp)
        config = root / "rejoin.conf"
        config.write_text("section: screens\n windows-host:\n windows:\nend\nsection: links\n windows-host:\n  right = windows\n windows:\n  left = windows-host\nend\n"
                          "section: options\n clipboardSharing = false\nend\n", encoding="utf-8")
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0)); port = free.getsockname()[1]
        processes.append(subprocess.Popen([str(binary / "cursorway-server.exe"), "-f", "--no-tray", "--name", "windows-host", "--debug", "INFO",
            "--profile-dir", str(host), "-c", str(config), "--address", "127.0.0.1:" + str(port), "--log", str(server_log)], stdout=console, stderr=subprocess.STDOUT))
        def start_client():
            return subprocess.Popen([str(binary / "cursorway-client.exe"), "-f", "--no-tray", "--name", "windows", "--debug", "INFO",
                "--profile-dir", str(receiver), "--log", str(client_log), "127.0.0.1:" + str(port)], stdout=console, stderr=subprocess.STDOUT)
        client = start_client(); processes.append(client)
        wait(lambda: 'client "windows" has connected' in read(server_log), "receiver did not connect")
        # Push the pointer through the right edge until the host switches to the receiver.
        width = user32.GetSystemMetrics(0)
        def switched(): return 'switch from "windows-host" to "windows"' in read(server_log)
        for _ in range(60):
            user32.SetCursorPos(width - 40, 300)
            for _ in range(8): user32.mouse_event(MOUSEEVENTF_MOVE, 30, 0, 0, 0); time.sleep(0.01)
            time.sleep(0.15)
            if switched(): break
        assert switched(), "host never switched to the receiver"
        # The desktop switch: the receiver's core goes away and a new one starts right away.
        client.kill(); client.wait(); started = time.monotonic()
        client = start_client(); processes.append(client)
        wait(lambda: read(server_log).count('client "windows" has connected') >= 2, "receiver did not reconnect")
        took = time.monotonic() - started
        wait(lambda: 'client "windows" is back, returning the cursor to it' in read(server_log), "host did not return the cursor to the receiver", 5)
        print("::notice title=Rejoin::new receiver core connected %.2f s after the old one was killed" % took)
        assert took < 4, "reconnecting took %.2f s" % took
        print("PASS: the receiver's core was replaced and the host put the cursor back on it (%.2f s)" % took)
    except Exception as failure:
        console.flush()
        # Job logs need a token to read; annotations do not.
        lines = [l for l in read(server_log).splitlines() if any(k in l for k in ("switch", "connected", "disconnected", "is back", "jump", "ERROR", "WARN"))]
        print("::error title=Rejoin::%s%%0A%s" % (" ".join(str(failure).splitlines()), "%0A".join(l[-160:] for l in lines[-25:])))
        for log in [server_log, client_log, root / "console.log"]:
            if log.exists(): print("==", log.name); print(read(log)[-6000:])
        raise
    finally:
        for p in processes:
            if p.poll() is None: p.kill()
        for p in processes: p.wait()
        console.close()
