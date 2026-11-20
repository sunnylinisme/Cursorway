"""Production server + 8 production clients over mutual TLS with a 9 x 1 arrangement (host + 8 in a row).

wide-row.conf is what the Mac arrange editor writes for the 一排・主控最左 preset with eight receivers
(the Mac self-test checks the same chain): every screen links only to its neighbours. The server must
accept the config and every client must connect and stay connected.
"""
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
config = pathlib.Path(__file__).with_name("wide-row.conf")
names = re.findall(r"^ (r-[0-9a-f]{16}):$", config.read_text(encoding="utf-8").split("section: aliases")[0], re.M)
assert len(names) == 8, names
processes = []
with tempfile.TemporaryDirectory(prefix="cursorway-wide-") as temporary:
    root = pathlib.Path(temporary)
    console = open(root / "console.log", "w", encoding="utf-8")
    server_log = root / "server.log"
    try:
        def pair(*args):
            return subprocess.check_output([str(binary / "cursorway-pair.exe"), *map(str, args)], text=True).strip()
        server_profile = root / "host"
        server_fingerprint = pair("init", server_profile)
        clients = []
        for name in names:
            profile = root / name
            pair("trust", server_profile, "client", pair("init", profile))
            pair("trust", profile, "server", server_fingerprint)
            clients.append((name, profile))
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0)); port = free.getsockname()[1]
        processes.append(subprocess.Popen([str(binary / "cursorway-server.exe"), "-f", "--no-tray", "--name", "windows-host",
            "--debug", "INFO", "--profile-dir", str(server_profile), "-c", str(config),
            "--address", "127.0.0.1:" + str(port), "--log", str(server_log)], stdout=console, stderr=subprocess.STDOUT))
        time.sleep(2)
        assert processes[0].poll() is None, "server exited; config rejected?"
        for name, profile in clients:
            processes.append(subprocess.Popen([str(binary / "cursorway-client.exe"), "-f", "--no-tray", "--name", name,
                "--profile-dir", str(profile), "--log", str(root / (name + ".log")), "127.0.0.1:" + str(port)],
                stdout=console, stderr=subprocess.STDOUT))
        connected = set()
        for _ in range(60):
            text = server_log.read_text(encoding="utf-8", errors="replace") if server_log.exists() else ""
            connected = set(re.findall(r'client "(r-[0-9a-f]{16})" has connected', text))
            if connected == set(names):
                break
            time.sleep(0.5)
        assert connected == set(names), "connected: %s, missing: %s" % (sorted(connected), sorted(set(names) - connected))
        # Stay connected: no client drops out over a few keep-alive rounds.
        time.sleep(5)
        text = server_log.read_text(encoding="utf-8", errors="replace")
        dropped = re.findall(r'client "(r-[0-9a-f]{16})" has disconnected', text)
        assert not dropped, "disconnected: %s" % dropped
        assert all(p.poll() is None for p in processes), "a process exited"
        print("PASS: 9 x 1 arrangement, server + 8 clients connected over mutual TLS and stayed connected")
    except Exception:
        console.flush()
        for log in [server_log, root / "console.log"]:
            if log.exists():
                print("==", log.name); print(log.read_text(encoding="utf-8", errors="replace")[-6000:])
        raise
    finally:
        for p in processes:
            p.kill()
        for p in processes:
            p.wait()
        console.close()
