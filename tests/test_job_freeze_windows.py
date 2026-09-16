"""The membership freeze against the real kernel, not a stand-in.

Everything else about the repair is driven through a scripted inspector. This test
exists so a wrong structure layout or a wrong access mask cannot pass unnoticed: it
creates a real Job, applies the real limit through the same inspector the repair uses,
and proves the limit is what stops a process from joining, by restoring it and watching
the same process join successfully.

It needs no elevation: the Job, its child processes and the handles are all this
process's own.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import recovery, winapi  # noqa: E402


CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
FULL_ACCESS = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE


@unittest.skipUnless(sys.platform == "win32", "Job objects are Windows-only")
class JobStructureTests(unittest.TestCase):
    @unittest.skipUnless(ctypes.sizeof(ctypes.c_void_p) == 8, "x64 layout")
    def test_the_limit_structures_match_the_documented_x64_layout(self) -> None:
        self.assertEqual(ctypes.sizeof(winapi.JOBOBJECT_BASIC_LIMIT_INFORMATION), 64)
        self.assertEqual(ctypes.sizeof(winapi.IO_COUNTERS), 48)
        self.assertEqual(ctypes.sizeof(winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION), 144)
        self.assertEqual(winapi.JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags.offset, 16)
        self.assertEqual(winapi.JOBOBJECT_BASIC_LIMIT_INFORMATION.ActiveProcessLimit.offset, 40)


@unittest.skipUnless(sys.platform == "win32", "Job objects are Windows-only")
class RealFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        kernel32 = winapi.kernel32
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            self.skipTest("this process may not create a Job object")
        self.job_handle = int(handle)
        self.addCleanup(winapi.close_handle, self.job_handle)
        self.record = recovery.JobRecord(1, 1, self.job_handle, FULL_ACCESS, r"\Container_Test", [])
        self.inspector = recovery.WindowsJobInspector()

    def start_child(self) -> subprocess.Popen:
        """A suspended child: it never runs, and it is killed when the test ends."""
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            creationflags=CREATE_SUSPENDED | CREATE_NO_WINDOW,
        )
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        return child

    def assign(self, child: subprocess.Popen) -> bool:
        return bool(winapi.kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(self.job_handle), wintypes.HANDLE(int(child._handle))
        ))

    def test_the_freeze_is_what_stops_a_process_from_joining(self) -> None:
        first = self.start_child()
        self.assertTrue(self.assign(first), "the first child should join the Job")
        self.assertIn(first.pid, self.inspector.pids(self.record))

        freeze = self.inspector.duplicate_for_freeze(self.record)
        self.addCleanup(winapi.close_handle, freeze)
        saved = self.inspector.query_limits(freeze)
        self.assertEqual(self.inspector.accounting(freeze), 1)

        self.inspector.set_active_process_limit(freeze, 1)
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(self.inspector.query_limits(freeze))
        self.assertTrue(limits.BasicLimitInformation.LimitFlags & winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        self.assertEqual(limits.BasicLimitInformation.ActiveProcessLimit, 1)

        blocked = self.start_child()
        self.assertFalse(self.assign(blocked), "a second process must not join a frozen Job")

        # Known-bad control: with the limit restored, the very same call succeeds, so
        # the refusal above was caused by the freeze and by nothing else.
        self.inspector.restore_limits(freeze, saved)
        restored = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(self.inspector.query_limits(freeze))
        self.assertFalse(restored.BasicLimitInformation.LimitFlags & winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        allowed = self.start_child()
        self.assertTrue(self.assign(allowed), "with the freeze lifted the same call joins")

    def test_termination_empties_the_job(self) -> None:
        child = self.start_child()
        self.assertTrue(self.assign(child))
        self.assertIn(child.pid, self.inspector.pids(self.record))
        self.inspector.terminate(self.record)
        self.assertEqual(self.inspector.pids(self.record), [])


if __name__ == "__main__":
    unittest.main()
