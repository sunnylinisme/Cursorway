"""Creates a desktop named CursorwayTest, makes it the input desktop for a few seconds, then
switches back to Default (what Windows does for a UAC prompt or Ctrl+Alt+Del, in miniature).
Usage: windows-switch-desktop.py <seconds>"""
import ctypes
import sys
import time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.CreateDesktopW.restype = wintypes.HANDLE; user32.OpenDesktopW.restype = wintypes.HANDLE
GENERIC_ALL = 0x10000000
test = user32.CreateDesktopW("CursorwayTest", None, None, 0, GENERIC_ALL, None)
if not test: raise ctypes.WinError(ctypes.get_last_error())
default = user32.OpenDesktopW("Default", 0, False, GENERIC_ALL)
if not default: raise ctypes.WinError(ctypes.get_last_error())
try:
    if not user32.SwitchDesktop(test): raise ctypes.WinError(ctypes.get_last_error())
    time.sleep(float(sys.argv[1]))
finally:
    for _ in range(20):
        if user32.SwitchDesktop(default): break
        time.sleep(.1)
    user32.CloseDesktop(test); user32.CloseDesktop(default)
print("switched to CursorwayTest and back")
