"""Elevation: the request that is made, and the diagnostic that survives it.

Every way the elevated child can fail to start must leave an explanation on disk. The
parent therefore keeps its own log until the child has actually written one, and it
decides that by comparing the file before and after, never by comparing timestamps with
its own clock: a file server minutes behind the workstation must not cost a diagnostic.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import elevation, payload, reporting, winapi  # noqa: E402
from clauderestart.errors import RecoveryError  # noqa: E402


CHILD_LOG = "[INSTALLED] the elevated run did its work\n"


class ElevationLayoutTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8, "x64 Windows layout")
    def test_shellexecuteinfo_layout_matches_win64(self) -> None:
        self.assertEqual(ctypes.sizeof(winapi.SHELLEXECUTEINFOW), 112)


class ElevationRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / payload.CONSOLE_EXE_NAME
        self.exe.write_bytes(b"")

    def test_elevation_request_frozen_has_no_script_argument(self) -> None:
        with support.frozen_at(self.exe):
            target, parameters, workdir = elevation.elevation_request(["--yes", "--pause", "--elevated"])
        self.assertEqual(Path(target), self.exe)
        self.assertEqual(parameters, "--yes --pause --elevated")
        self.assertEqual(Path(workdir), self.root)

    def test_elevation_request_from_source_keeps_the_entry_script_first(self) -> None:
        target, parameters, workdir = elevation.elevation_request(["--yes"])
        script = str(payload.SOURCE_ENTRY)
        self.assertEqual(Path(target), Path(sys.executable).resolve())
        self.assertTrue(parameters.startswith(script) or parameters.startswith(f'"{script}"'), parameters)
        self.assertTrue(parameters.endswith("--yes --elevated"), parameters)
        self.assertEqual(Path(workdir), support.ROOT)


@unittest.skipUnless(sys.platform == "win32", "elevation is a Windows operation")
class ElevatedLogTests(unittest.TestCase):
    """What ends up on disk for each way the elevated run can go."""

    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / payload.CONSOLE_EXE_NAME
        self.exe.write_bytes(b"")
        self.log = self.root / payload.LOG_FILE_NAME
        self.parent_log = self.root / payload.PARENT_LOG_FILE_NAME
        self.frozen = support.frozen_at(self.exe)
        self.frozen.__enter__()
        self.addCleanup(self.frozen.close)
        self.reporter = reporting.Reporter()
        self.reporter.emit("UAC", "Requesting administrator access.")

    def fake_shell(self, *, started: bool, handle: int = 0x1234, last_error: int = 0):
        def shell_execute(info_pointer):
            ctypes.set_last_error(last_error)
            if not started:
                return 0
            # byref() hands over a CArgObject, so the structure is reached through the
            # object it wraps, not through .contents.
            info_pointer._obj.hProcess = handle
            return 1

        return shell_execute

    def relaunch(self, *, started=True, handle=0x1234, last_error=0, wait=0, exit_code=0, exit_ok=True, child=None):
        """Drive relaunch_elevated with the Windows calls replaced."""

        def wait_for(_handle, _timeout):
            if child is not None:
                child()
            return wait

        def get_exit_code(_handle, pointer):
            pointer._obj.value = exit_code
            return 1 if exit_ok else 0

        with mock.patch.object(winapi.shell32, "ShellExecuteExW", self.fake_shell(started=started, handle=handle, last_error=last_error)), \
             mock.patch.object(winapi.kernel32, "WaitForSingleObject", wait_for), \
             mock.patch.object(winapi.kernel32, "GetExitCodeProcess", get_exit_code), \
             mock.patch.object(winapi, "close_handle", lambda _handle: None):
            return elevation.relaunch_elevated(self.reporter)

    def save(self) -> Path | None:
        """Save the way main does: not at all once the child owns the result log."""
        if not self.reporter.persist:
            return None
        return self.reporter.save(guard=self.reporter.log_guard)

    def assert_durable_log(self, expected: str) -> None:
        self.assertTrue(self.reporter.persist, "the parent must keep its own log")
        written = self.save()
        self.assertEqual(written, self.log)
        self.assertIn(expected, written.read_text(encoding="utf-8"))

    def test_a_cancelled_prompt_leaves_the_reason_on_disk(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            self.relaunch(started=False, last_error=winapi.ERROR_CANCELLED)
        self.reporter.emit("ERROR", str(stop.exception))
        self.assert_durable_log("cancelled")

    def test_a_failed_launch_leaves_the_reason_on_disk(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            self.relaunch(started=False, last_error=5)
        self.reporter.emit("ERROR", str(stop.exception))
        self.assert_durable_log("Administrator elevation was not started")

    def test_a_missing_process_handle_leaves_the_reason_on_disk(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            self.relaunch(handle=0)
        self.reporter.emit("ERROR", str(stop.exception))
        self.assert_durable_log("no process handle")

    def test_a_failed_wait_leaves_the_reason_on_disk(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            self.relaunch(wait=winapi.WAIT_FAILED)
        self.reporter.emit("ERROR", str(stop.exception))
        self.assert_durable_log("WaitForSingleObject")

    def test_a_failed_exit_code_read_leaves_the_reason_on_disk(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            self.relaunch(exit_ok=False)
        self.reporter.emit("ERROR", str(stop.exception))
        self.assert_durable_log("GetExitCodeProcess")

    def test_a_child_that_wrote_its_log_is_never_overwritten(self) -> None:
        def child() -> None:
            self.log.write_text(CHILD_LOG, encoding="utf-8")
            # An older timestamp than this machine's clock, as a file server can report.
            old = os.stat(self.log).st_mtime - 600
            os.utime(self.log, (old, old))

        code = self.relaunch(exit_code=0, child=child)
        self.assertEqual(code, 0)
        self.assertFalse(self.reporter.persist, "the child owns the result log")
        self.assertIsNone(self.save())
        self.assertEqual(self.log.read_text(encoding="utf-8"), CHILD_LOG)

    def test_a_child_that_wrote_no_log_leaves_the_parents_account(self) -> None:
        code = self.relaunch(exit_code=2)
        self.assertEqual(code, 2)
        self.assertTrue(self.reporter.persist)
        written = self.save()
        self.assertEqual(written, self.log)
        text = written.read_text(encoding="utf-8")
        self.assertIn("exit code 2", text)
        self.assertIn("left no log", text)

    def test_a_stale_log_from_an_earlier_run_is_replaced(self) -> None:
        self.log.write_text("[SELF-CHECK] an earlier run\n", encoding="utf-8")
        code = self.relaunch(exit_code=1)
        self.assertEqual(code, 1)
        written = self.save()
        self.assertEqual(written, self.log)
        self.assertNotIn("an earlier run", written.read_text(encoding="utf-8"))

    def test_a_log_written_after_the_check_is_not_replaced(self) -> None:
        # The child wrote nothing by the time the parent looked, then wrote afterwards.
        code = self.relaunch(exit_code=3)
        self.assertEqual(code, 3)
        self.log.write_text(CHILD_LOG, encoding="utf-8")
        written = self.save()
        self.assertEqual(written, self.parent_log, "the parent writes beside it, never over it")
        self.assertEqual(self.log.read_text(encoding="utf-8"), CHILD_LOG)


if __name__ == "__main__":
    unittest.main()
