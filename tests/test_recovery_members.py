"""Job member partitioning: who counts as exited and who stops the repair."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import recovery  # noqa: E402


class MemberValidationTests(unittest.TestCase):
    OPAQUE = recovery.ProcessInfo(200, "<exited or inaccessible>", "", "", None, None)
    SAME = recovery.ProcessInfo(201, "claude.exe", r"C:\x\claude.exe", "", 1, 5)
    FOREIGN = recovery.ProcessInfo(202, "claude.exe", r"C:\x\claude.exe", "", 2, 5)
    LIVE_UNKNOWN_SESSION = recovery.ProcessInfo(203, "claude.exe", r"C:\x\claude.exe", "", None, 5)

    def test_member_the_kernel_no_longer_lists_counts_as_exited(self) -> None:
        self.assertEqual(
            recovery._partition_members([self.OPAQUE, self.SAME], 1, still_in_job=[201]),
            ([200], []),
        )

    def test_opaque_member_still_in_the_job_stops_the_repair(self) -> None:
        # Fail closed: the kernel still lists PID 200, so it is live but unverifiable.
        self.assertEqual(
            recovery._partition_members([self.OPAQUE, self.SAME], 1, still_in_job=[200, 201]),
            ([], [200]),
        )

    def test_foreign_or_unknown_sessions_are_never_exited(self) -> None:
        self.assertEqual(
            recovery._partition_members([self.SAME, self.FOREIGN], 1, still_in_job=[201, 202]), ([], [202])
        )
        self.assertEqual(
            recovery._partition_members([self.LIVE_UNKNOWN_SESSION], 1, still_in_job=[203]), ([], [203])
        )
        self.assertEqual(recovery._partition_members([self.LIVE_UNKNOWN_SESSION], 1, still_in_job=[]), ([], [203]))
        self.assertEqual(recovery._partition_members([self.SAME], None, still_in_job=[201]), ([], [201]))


if __name__ == "__main__":
    unittest.main()
