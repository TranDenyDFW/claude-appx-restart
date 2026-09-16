"""A real TaskDialog, closed the way recovery closes the one a failed Claude click leaves.

The production dialog is shown by sihost.exe, which a test cannot drive, so a child process
shows the same kind of window: a comctl32 version 6 TaskDialog with an OK button, titled with
a Claude executable path. Only the owner rule is pointed at the child's interpreter; every
other rule runs exactly as it does in production.

Everything here is filtered to the child's own process id, so a real Claude error dialog open
on the machine running the tests is never inspected for dismissal, let alone closed.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import dialogs, reporting, winapi  # noqa: E402
from clauderestart.package import EXPECTED_PACKAGE_FAMILY, PackageInfo  # noqa: E402


CHILD = r'''
import ctypes
from ctypes import wintypes
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class ACTCTXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwFlags", wintypes.DWORD),
        ("lpSource", wintypes.LPCWSTR),
        ("wProcessorArchitecture", wintypes.USHORT),
        ("wLangId", wintypes.USHORT),
        ("lpAssemblyDirectory", wintypes.LPCWSTR),
        ("lpResourceName", ctypes.c_void_p),
        ("lpApplicationName", wintypes.LPCWSTR),
        ("hModule", wintypes.HMODULE),
    ]


# TaskDialog lives in comctl32 version 6, which a plain python.exe does not load. shell32
# carries a manifest resource (124) that selects it, so activate that before loading comctl32.
system = ctypes.create_unicode_buffer(260)
kernel32.GetSystemDirectoryW(system, 260)
context = ACTCTXW()
context.cbSize = ctypes.sizeof(ACTCTXW)
context.dwFlags = 0x008
context.lpSource = system.value + chr(92) + "shell32.dll"
context.lpResourceName = 124
kernel32.CreateActCtxW.restype = wintypes.HANDLE
kernel32.CreateActCtxW.argtypes = [ctypes.POINTER(ACTCTXW)]
handle = kernel32.CreateActCtxW(ctypes.byref(context))
if not handle or handle == ctypes.c_void_p(-1).value:
    print("CreateActCtxW failed", ctypes.get_last_error(), flush=True)
    sys.exit(90)
cookie = ctypes.c_size_t()
kernel32.ActivateActCtx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t)]
if not kernel32.ActivateActCtx(handle, ctypes.byref(cookie)):
    print("ActivateActCtx failed", ctypes.get_last_error(), flush=True)
    sys.exit(91)
comctl32 = ctypes.WinDLL("comctl32", use_last_error=True)
comctl32.TaskDialog.argtypes = [
    wintypes.HWND, wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
]
comctl32.TaskDialog.restype = ctypes.c_long
pressed = ctypes.c_int()
TDCBF_OK_BUTTON = 0x0001
TD_ERROR_ICON = 0xFFFE
result = comctl32.TaskDialog(
    None, None, sys.argv[1], None, "Another program is currently using this file.",
    TDCBF_OK_BUTTON, TD_ERROR_ICON, ctypes.byref(pressed),
)
if result != 0:
    print("TaskDialog failed", hex(result & 0xFFFFFFFF), flush=True)
    sys.exit(92)
sys.exit(pressed.value)
'''


@unittest.skipUnless(sys.platform == "win32", "task dialogs are Windows only")
class RealTaskDialogTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name).resolve()
        install = base / "WindowsApps" / "Claude_9.9.9.0_x64__pzs8sxrjxfjjc"
        self.title = str(install / "app" / "claude.exe")
        self.package = PackageInfo(
            "Claude",
            "9.9.9.0",
            "Claude_9.9.9.0_x64__pzs8sxrjxfjjc",
            EXPECTED_PACKAGE_FAMILY,
            str(install),
            "Claude",
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "",
            r"app\Claude.exe",
        )
        self.script = base / "show_task_dialog.py"
        self.script.write_text(CHILD, encoding="utf-8")
        self.backend = dialogs.WindowsWindowBackend()

    def stop(self, child: subprocess.Popen) -> None:
        if child.poll() is None:
            child.kill()  # only ever this test's own child
            child.wait(timeout=10)
        if child.stdout is not None:
            child.stdout.close()

    def show(self) -> tuple[subprocess.Popen, frozenset[str], dialogs.Candidate]:
        # A virtual environment's python.exe starts the real interpreter as a second process,
        # so the dialog would belong to another pid. Start the base interpreter directly.
        interpreter = getattr(sys, "_base_executable", None) or sys.executable
        child = subprocess.Popen(
            [interpreter, str(self.script), self.title],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.addCleanup(self.stop, child)
        last: dialogs.Candidate | None = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                output = child.stdout.read() if child.stdout is not None else ""
                self.fail(f"the child exited with {child.returncode} before showing its dialog: {output}")
            image = winapi.process_image_path(child.pid)
            owners = frozenset({os.path.normcase(image)}) if image else frozenset()
            mine = [item for item in dialogs.candidates(self.package, self.backend, owners) if item.pid == child.pid]
            if mine:
                last = mine[0]
                if last.matches:
                    return child, owners, last
            time.sleep(0.1)
        self.fail(f"the child's task dialog never matched: {last.reasons if last else 'no window appeared'}")

    def test_the_real_window_has_the_captured_shape(self) -> None:
        _child, _owners, found = self.show()
        classes = [self.backend.class_name(hwnd) for hwnd in self.backend.descendants(found.hwnd)]
        self.assertEqual(self.backend.class_name(found.hwnd), "#32770")
        self.assertEqual(self.backend.owner(found.hwnd), 0)
        self.assertIn("DirectUIHWND", classes)
        self.assertIn("Button", classes)
        self.assertEqual(found.title, self.title)

    def test_the_ok_button_is_pressed_and_the_dialog_closes(self) -> None:
        child, owners, found = self.show()
        reporter = reporting.Reporter()
        closed = dialogs.dismiss_after_green(
            self.package, dialogs.Snapshot((found,)), reporter, self.backend, owners, failure_logged=True
        )
        self.assertEqual(closed, 1, reporter.lines)
        self.assertFalse(self.backend.exists(found.hwnd) and self.backend.pid(found.hwnd) == child.pid)
        child.wait(timeout=10)
        # The dialog reports which button ended it, so this proves the OK button was pressed
        # rather than the window being destroyed some other way.
        self.assertEqual(child.returncode, winapi.IDOK)
        self.assertTrue(any("by TDM_CLICK_BUTTON" in line for line in reporter.lines), reporter.lines)

    def test_wm_close_alone_does_not_close_a_task_dialog(self) -> None:
        # The control that proves the button press is what works: a TaskDialog without
        # cancellation ignores WM_CLOSE, so a fallback that only closed would leave it open.
        child, _owners, found = self.show()
        self.backend.post_close(found.hwnd)
        time.sleep(1.0)
        self.assertTrue(self.backend.exists(found.hwnd))
        self.assertIsNone(child.poll(), "WM_CLOSE ended the dialog, so it is not the control it claims to be")
        self.assertTrue(self.backend.click_ok(found.hwnd))
        child.wait(timeout=10)
        self.assertEqual(child.returncode, winapi.IDOK)


if __name__ == "__main__":
    unittest.main()
