"""A real TaskDialog, closed the way recovery closes the one a failed Claude click leaves.

The production dialog is shown by sihost.exe, which a test cannot drive, so a child process
shows the same kind of window: a comctl32 version 6 TaskDialog with an OK button, titled with
a Claude executable path. Only the owner rule is pointed at the child's interpreter; every
other rule runs exactly as it does in production.

The dialog is created on a private desktop that is never displayed, and every look at it is
made from a thread attached to that desktop. A test dialog on the visible desktop takes focus
from whoever is at the keyboard, which is how an earlier version of this test interrupted
someone's work. The child refuses to create any window unless it is on the private desktop, and
a test asserts the dialog cannot be seen from the visible desktop.

Everything is also filtered to the child's own process id, so a real Claude error dialog open
on the machine running the tests is never inspected for dismissal, let alone closed.

This needs an interactive session, as on a desktop or the CI runner. In a service session, such
as one reached over SSH, no window ever becomes visible and these tests fail.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import dialogs, reporting, winapi  # noqa: E402
from clauderestart.package import EXPECTED_PACKAGE_FAMILY, PackageInfo  # noqa: E402


GENERIC_ALL = 0x10000000

CHILD = r'''
import ctypes
from ctypes import wintypes
import sys

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenDesktopW.restype = wintypes.HANDLE
user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
user32.SetThreadDesktop.restype = wintypes.BOOL
desktop = user32.OpenDesktopW(sys.argv[2], 0, False, 0x10000000)
if not desktop:
    print("OpenDesktopW failed", ctypes.get_last_error(), flush=True)
    sys.exit(93)
if not user32.SetThreadDesktop(desktop):
    # Never fall back to the visible desktop: no window is created unless it is private.
    print("SetThreadDesktop failed", ctypes.get_last_error(), flush=True)
    sys.exit(94)

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


def desktop_api() -> ctypes.WinDLL:
    """A private user32 instance, so these argtypes never touch the one the package configures."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.CreateDesktopW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    user32.CreateDesktopW.restype = wintypes.HANDLE
    user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
    user32.SetThreadDesktop.restype = wintypes.BOOL
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.restype = wintypes.BOOL
    return user32


@unittest.skipUnless(sys.platform == "win32", "task dialogs are Windows only")
class RealTaskDialogTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.user32 = desktop_api()
        self.desktop_name = f"ClaudeRestartTest{os.getpid()}{id(self)}"
        self.desktop = self.user32.CreateDesktopW(self.desktop_name, None, None, 0, GENERIC_ALL, None)
        if not self.desktop:
            self.fail(f"could not create the private desktop: {ctypes.WinError(ctypes.get_last_error())}")
        self.addCleanup(self.user32.CloseDesktop, self.desktop)

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

    def on_private_desktop(self, work):
        """Run `work` on a thread attached to the private desktop, and return its result.

        A thread can only see and message windows on its own desktop, and it can only move to
        another desktop while it owns no windows, so each look uses a fresh thread.
        """
        results: queue.Queue = queue.Queue()

        def run() -> None:
            try:
                if not self.user32.SetThreadDesktop(self.desktop):
                    results.put((False, ctypes.WinError(ctypes.get_last_error())))
                    return
                results.put((True, work()))
            except BaseException as exc:  # noqa: BLE001 - re-raised on the test thread
                results.put((False, exc))

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(30)
        succeeded, value = results.get(timeout=1)
        if not succeeded:
            raise value
        return value

    def stop(self, child: subprocess.Popen) -> None:
        if child.poll() is None:
            child.kill()  # only ever this test's own child
            child.wait(timeout=10)
        if child.stdout is not None:
            child.stdout.close()

    def owners(self, child: subprocess.Popen) -> frozenset[str]:
        image = winapi.process_image_path(child.pid)
        return frozenset({os.path.normcase(image)}) if image else frozenset()

    def start_child(self) -> subprocess.Popen:
        # A virtual environment's python.exe starts the real interpreter as a second process,
        # so the dialog would belong to another pid. Start the base interpreter directly.
        interpreter = getattr(sys, "_base_executable", None) or sys.executable
        child = subprocess.Popen(
            [interpreter, str(self.script), self.title, self.desktop_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.addCleanup(self.stop, child)
        return child

    def child_windows(self, child: subprocess.Popen, owners: frozenset[str]) -> list[dialogs.Candidate]:
        """The child's dialogs as seen from whichever desktop the calling thread is on."""
        return [item for item in dialogs.candidates(self.package, self.backend, owners) if item.pid == child.pid]

    def show(self) -> tuple[subprocess.Popen, frozenset[str], dialogs.Candidate]:
        child = self.start_child()
        last: dialogs.Candidate | None = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                output = child.stdout.read() if child.stdout is not None else ""
                self.fail(f"the child exited with {child.returncode} before showing its dialog: {output}")
            owners = self.owners(child)
            mine = self.on_private_desktop(lambda: self.child_windows(child, owners))
            if mine:
                last = mine[0]
                if last.matches:
                    return child, owners, last
            time.sleep(0.1)
        self.fail(f"the child's task dialog never matched: {last.reasons if last else 'no window appeared'}")

    def test_an_empty_desktop_enumerates_to_nothing_rather_than_an_error(self) -> None:
        # EnumWindows returns FALSE with no error on a desktop with no windows. Treating that
        # as a failure would make every look at a quiet desktop report an error.
        self.assertEqual(self.on_private_desktop(self.backend.top_level_windows), [])

    def test_the_test_dialog_is_never_on_the_visible_desktop(self) -> None:
        # Watch both desktops from the moment the child starts. Looking only after the dialog was
        # found on the private desktop could never see one that went to the visible desktop,
        # because it would never be found there in the first place.
        child = self.start_child()
        seen_on_private = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not seen_on_private:
            if child.poll() is not None:
                output = child.stdout.read() if child.stdout is not None else ""
                self.fail(f"the child exited with {child.returncode} before showing its dialog: {output}")
            owners = self.owners(child)
            self.assertEqual(
                self.child_windows(child, owners), [], "the test dialog would take focus from whoever is working"
            )
            seen_on_private = bool(self.on_private_desktop(lambda: self.child_windows(child, owners)))
            if not seen_on_private:
                time.sleep(0.1)
        self.assertTrue(seen_on_private, "the child's dialog never appeared on the private desktop")
        self.assertEqual(
            self.child_windows(child, self.owners(child)), [], "the test dialog would take focus from whoever is working"
        )

    def test_the_real_window_has_the_captured_shape(self) -> None:
        _child, _owners, found = self.show()
        classes = self.on_private_desktop(
            lambda: [self.backend.class_name(hwnd) for hwnd in self.backend.descendants(found.hwnd)]
        )
        self.assertEqual(self.on_private_desktop(lambda: self.backend.class_name(found.hwnd)), "#32770")
        self.assertEqual(self.on_private_desktop(lambda: self.backend.owner(found.hwnd)), 0)
        self.assertIn("DirectUIHWND", classes)
        self.assertIn("Button", classes)
        self.assertEqual(found.title, self.title)

    def test_the_ok_button_is_pressed_and_the_dialog_closes(self) -> None:
        child, owners, found = self.show()
        reporter = reporting.Reporter()
        closed = self.on_private_desktop(
            lambda: dialogs.dismiss_after_green(
                self.package, dialogs.Snapshot((found,)), reporter, self.backend, owners, failure_logged=True
            )
        )
        self.assertEqual(closed, 1, reporter.lines)
        child.wait(timeout=10)
        # The dialog reports which button ended it, so this proves the OK button was pressed
        # rather than the window being destroyed some other way.
        self.assertEqual(child.returncode, winapi.IDOK)
        self.assertTrue(any("by TDM_CLICK_BUTTON" in line for line in reporter.lines), reporter.lines)

    def test_wm_close_alone_does_not_close_a_task_dialog(self) -> None:
        # The control that proves the button press is what works: a TaskDialog without
        # cancellation ignores WM_CLOSE, so a fallback that only closed would leave it open.
        child, _owners, found = self.show()
        self.on_private_desktop(lambda: self.backend.post_close(found.hwnd))
        time.sleep(1.0)
        self.assertTrue(self.on_private_desktop(lambda: self.backend.exists(found.hwnd)))
        self.assertIsNone(child.poll(), "WM_CLOSE ended the dialog, so it is not the control it claims to be")
        self.assertTrue(self.on_private_desktop(lambda: self.backend.click_ok(found.hwnd)))
        child.wait(timeout=10)
        self.assertEqual(child.returncode, winapi.IDOK)


if __name__ == "__main__":
    unittest.main()
