"""--harden (the service's UI access receiver core): another program of the same user, without
administrator rights, must not be able to open the core to change it, while it can open a core
started without --harden (the control). The hardened core also allows only Microsoft-signed DLLs.

Both cores and the probe run through "runas /trustlevel:0x20000" (the same user as a basic user),
so they share a user and an integrity level and only the hardening differs."""
import ctypes
import pathlib
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes

if len(sys.argv) == 4 and sys.argv[1] == "--probe":
    # Probe mode, run as the basic user: try to open the process for writing its memory.
    PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD = 0x0020, 0x0008, 0x0002
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True); kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, False, int(sys.argv[2]))
    error = ctypes.get_last_error()
    if handle: kernel32.CloseHandle(handle)
    pathlib.Path(sys.argv[3]).write_text("opened" if handle else "denied %d" % error)
    sys.exit(0)

binary = pathlib.Path(sys.argv[1]).resolve()
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True); kernel32.OpenProcess.restype = wintypes.HANDLE
with tempfile.TemporaryDirectory(prefix="cursorway-harden-") as temporary:
    root = pathlib.Path(temporary)
    def basic_user(name, command):
        script = root / (name + ".cmd"); script.write_text("@" + command + "\r\n", encoding="mbcs")
        subprocess.run(["runas", "/trustlevel:0x20000", str(script)], check=True, capture_output=True)
    def wait(check, what, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = check()
            if value: return value
            time.sleep(.2)
        raise AssertionError(what)
    def core_pid(marker):
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
            "(Get-CimInstance Win32_Process -Filter \"Name='cursorway-client.exe'\" | Where-Object { $_.CommandLine -like '*%s*' }).ProcessId" % marker], capture_output=True, text=True).stdout.strip()
        return int(out) if out.isdigit() else None
    results = {}
    pids = []
    try:
        for name, harden in (("plain", False), ("hardened", True)):
            profile = root / name; profile.mkdir()
            subprocess.check_output([str(binary / "cursorway-pair.exe"), "init", str(profile)])
            log = root / (name + ".log")
            # Port 1 never answers: the core keeps retrying, which is all this test needs.
            basic_user(name, '"%s" -f --no-tray --profile-dir "%s" --log "%s" --name harden-%s %s 127.0.0.1:1' % (binary / "cursorway-client.exe", profile, log, name, "--harden" if harden else ""))
            pid = wait(lambda: core_pid("harden-" + name), name + " core did not start"); pids.append(pid)
            time.sleep(1)
            out = root / (name + ".result")
            basic_user(name + "-probe", '"%s" "%s" --probe %d "%s"' % (sys.executable, pathlib.Path(__file__).resolve(), pid, out))
            results[name] = wait(lambda: out.exists() and out.read_text(), name + " probe did not answer")
            if harden:
                # GetProcessMitigationPolicy(ProcessSignaturePolicy = 8): bit 0 MicrosoftSignedOnly.
                handle = kernel32.OpenProcess(0x0400, False, pid); flags = wintypes.DWORD()
                ok = handle and kernel32.GetProcessMitigationPolicy(wintypes.HANDLE(handle), 8, ctypes.byref(flags), ctypes.sizeof(flags))
                if handle: kernel32.CloseHandle(handle)
                assert ok and flags.value & 1, "Hardened core allows DLLs that are not Microsoft-signed"
                assert "harden: other programs cannot change this process; Microsoft-signed DLLs only: on" in log.read_text(errors="replace"), log.read_text(errors="replace")[-3000:]
        print("::notice title=Harden::basic user opening the plain core: %s; the hardened core: %s" % (results["plain"], results["hardened"]))
        assert results["plain"] == "opened", "Control failed: a basic user could not open the plain core either (%s), so the test proves nothing" % results["plain"]
        assert results["hardened"].startswith("denied"), "A basic user of the same account opened the hardened core for writing"
        print("PASS: a program of the same user cannot open the hardened core (it can open a plain one), and only Microsoft-signed DLLs load into it")
    finally:
        for pid in pids:
            handle = kernel32.OpenProcess(0x0001, False, pid)
            if handle: kernel32.TerminateProcess(wintypes.HANDLE(handle), 0); kernel32.CloseHandle(handle)
