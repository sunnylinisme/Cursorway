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
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
def report(kind, value, trace):
    import traceback
    print("::error title=Harden::" + "%0A".join("".join(traceback.format_exception(kind, value, trace)).splitlines()[-12:]), flush=True)
    sys.__excepthook__(kind, value, trace)
sys.excepthook = report
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True); kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.SetLastError(0)
with tempfile.TemporaryDirectory(prefix="cursorway-harden-") as temporary:
    root = pathlib.Path(temporary)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    def basic_token():
        # The same user as a basic user (SAFER "normal user" level, medium integrity): what any
        # program of this user without administrator rights would be.
        level = wintypes.HANDLE(); token = wintypes.HANDLE()
        assert advapi32.SaferCreateLevel(2, 0x20000, 1, ctypes.byref(level), None), ctypes.WinError(ctypes.get_last_error())
        assert advapi32.SaferComputeTokenFromLevel(level, None, ctypes.byref(token), 0, None), ctypes.WinError(ctypes.get_last_error())
        advapi32.SaferCloseLevel(level)
        sid = ctypes.c_void_p()
        assert advapi32.ConvertStringSidToSidW("S-1-16-8192", ctypes.byref(sid)), ctypes.WinError(ctypes.get_last_error())
        class LABEL(ctypes.Structure): _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]
        label = LABEL(sid, 0x20)
        assert advapi32.SetTokenInformation(token, 25, ctypes.byref(label), ctypes.sizeof(label) + advapi32.GetLengthSid(sid)), ctypes.WinError(ctypes.get_last_error())
        return token
    def open_as_basic_user(pid):
        # What such a program gets when it opens the core to write its memory or start a thread in it.
        token = basic_token()
        assert advapi32.ImpersonateLoggedOnUser(token), ctypes.WinError(ctypes.get_last_error())
        try:
            handle = kernel32.OpenProcess(0x0020 | 0x0008 | 0x0002, False, pid); error = ctypes.get_last_error()
        finally:
            advapi32.RevertToSelf(); kernel32.CloseHandle(token)
        if handle: kernel32.CloseHandle(handle); return "opened"
        return "denied %d" % error
    def basic_user(name, command):
        token = basic_token()
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR)] + \
                       [(n, wintypes.DWORD) for n in ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + \
                       [("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]
        startup = STARTUPINFO(); startup.cb = ctypes.sizeof(startup); info = PROCESS_INFORMATION()
        line = ctypes.create_unicode_buffer(command)
        ok = advapi32.CreateProcessAsUserW(token, None, line, None, None, False, 0x08000000, None, None, ctypes.byref(startup), ctypes.byref(info))
        error = ctypes.get_last_error(); kernel32.CloseHandle(token)
        assert ok, "Cannot start %s as a basic user: %s" % (name, ctypes.WinError(error))
        kernel32.CloseHandle(info.hThread); kernel32.CloseHandle(info.hProcess)
        return info.dwProcessId
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
            pid = basic_user(name, '"%s" -f --no-tray --profile-dir "%s" --log "%s" --name harden-%s %s 127.0.0.1:1' % (binary / "cursorway-client.exe", profile, log, name, "--harden" if harden else ""))
            pids.append(pid); time.sleep(1.5)
            alive = kernel32.OpenProcess(0x1000, False, pid); code = wintypes.DWORD()
            assert alive and kernel32.GetExitCodeProcess(wintypes.HANDLE(alive), ctypes.byref(code)) and code.value == 259, name + " core exited at once: " + (log.read_text(errors="replace")[-2000:] if log.exists() else "no log")
            results[name] = open_as_basic_user(pid)
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
