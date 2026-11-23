"""Runs a command as the same user without administrator rights (SAFER "normal user" level,
medium integrity) and waits for it: CI runs as an administrator, the user usually does not.
Usage: windows-basic-user-run.py <timeout seconds> <command line>; exits with the command's code."""
import ctypes
import sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


def basic_token():
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


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR)] + \
               [(n, wintypes.DWORD) for n in ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + \
               [("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


if __name__ == "__main__":
    timeout, command = float(sys.argv[1]), sys.argv[2]
    token = basic_token(); startup = STARTUPINFO(); startup.cb = ctypes.sizeof(startup); info = PROCESS_INFORMATION()
    if not advapi32.CreateProcessAsUserW(token, None, ctypes.create_unicode_buffer(command), None, None, False, 0x08000000, None, None, ctypes.byref(startup), ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel32.CloseHandle(info.hThread)
    if kernel32.WaitForSingleObject(info.hProcess, int(timeout * 1000)) != 0:
        kernel32.TerminateProcess(info.hProcess, 1); print("timed out"); sys.exit(2)
    code = wintypes.DWORD(); kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    sys.exit(code.value)
