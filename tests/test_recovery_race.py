"""The Job membership race: nothing is terminated that was not verified.

Every case drives the real repair driver through a scripted inspector, so these are
tests of the code that runs during an incident, not of a second copy. The rule they
enforce: a Job that gains a member at any point is refused outright, a Job that only
loses members may be re-validated a bounded number of times, and a process number that
was reused can never pass.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import recovery, reporting, winapi  # noqa: E402
from clauderestart.errors import RecoveryError, SafetyStop  # noqa: E402
from clauderestart.fakes import FakeJobInspector  # noqa: E402


JOB_NAME = r"\Container_Claude_1.0.0.0_x64__pzs8sxrjxfjjc-S-1-5-21-1-2-3-1001"
APPINFO_PID = 4242
FULL_ACCESS = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE


def make_job(access: int = FULL_ACCESS) -> recovery.JobRecord:
    return recovery.JobRecord(9, 9, 0x1234, access, JOB_NAME, [101, 102])


def info(pid: int, creation: int | None, session: int | None = 1) -> recovery.ProcessInfo:
    return recovery.ProcessInfo(pid, "claude.exe", r"C:\x\claude.exe", "", session, creation)


class FailingInspector(FakeJobInspector):
    """A scripted inspector that fails one specific query, to test the abort paths."""

    def __init__(self, *args, fail_pids_at: int | None = None, error: Exception | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fail_pids_at = fail_pids_at
        self._error = error or RecoveryError("the Job could not be queried")

    def pids(self, job):
        if self._fail_pids_at is not None and self.pid_calls + 1 == self._fail_pids_at:
            self.pid_calls += 1
            raise self._error
        return super().pids(job)


class LeakedLimitTests(unittest.TestCase):
    """A run killed while the freeze was applied leaves its limit on the obsolete Job.

    The documentation promises the next run reports that and replaces it. Only the scan path
    reported it, so the promise was false for every repair.
    """

    def repair(self, inspector) -> int:
        self.reporter = reporting.Reporter()
        return recovery.repair_stale_job(make_job(), APPINFO_PID, self.reporter, inspector, 3)

    def notes(self) -> list[str]:
        return [line for line in self.reporter.lines if "already carries an active process limit" in line]

    def test_a_limit_left_by_a_killed_run_is_reported(self) -> None:
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        limits.BasicLimitInformation.ActiveProcessLimit = 7
        inspector = FakeJobInspector([[101, 102]], saved_limits=bytes(limits))
        self.repair(inspector)
        self.assertEqual(len(self.notes()), 1, self.reporter.lines)
        self.assertIn("7", self.notes()[0])
        # The limit that was there is still put back, rather than left as this run set it.
        self.assertEqual(len(inspector.restore_calls), 1)
        self.assertEqual(inspector.restore_calls[0], bytes(limits))

    def test_a_job_with_no_previous_limit_is_not_reported(self) -> None:
        self.repair(FakeJobInspector([[101, 102]]))
        self.assertEqual(self.notes(), [])


class GrowthTests(unittest.TestCase):
    def repair(self, inspector, job=None, attempts=3):
        return recovery.repair_stale_job(job or make_job(), APPINFO_PID, reporting.Reporter(), inspector, attempts)

    def test_a_member_added_during_validation_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101, 102, 103]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        # Assert the reason, not just the PID: without the growth guard the same PID reaches the
        # unverified check, whose message also names it, so a PID-only assertion cannot fail.
        message = str(stop.exception)
        self.assertIn("gained member", message)
        self.assertIn("103", message)
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_member_added_after_validation_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101, 102], [101, 102, 103]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("after validation", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_member_added_between_the_final_snapshots_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101, 102], [101, 102], [101, 102, 103]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("appeared after validation", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_reused_process_number_stops_the_repair(self) -> None:
        inspector = FakeJobInspector(
            [[101, 102]], info={102: [info(102, 5), info(102, 99)]}
        )
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("reused", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_member_that_cannot_be_verified_before_termination_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[101, 102]], info={102: [info(102, 5), info(102, None)]})
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("could not be verified", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_member_in_another_session_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[101, 102]], info={102: info(102, 5, session=2)})
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("could not be verified", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_a_protected_process_number_stops_the_repair(self) -> None:
        inspector = FakeJobInspector([[4, 101]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("protected", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)


class RetryTests(unittest.TestCase):
    def repair(self, inspector, attempts=3):
        return recovery.repair_stale_job(make_job(), APPINFO_PID, reporting.Reporter(), inspector, attempts)

    def test_a_member_leaving_during_validation_is_retried_and_succeeds(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101]])
        self.assertEqual(self.repair(inspector), 1)
        self.assertEqual(inspector.terminate_calls, 1)
        self.assertEqual(inspector.set_limit_calls, [1])

    def test_a_member_leaving_after_validation_is_retried_and_succeeds(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101, 102], [101]])
        self.assertEqual(self.repair(inspector), 1)
        self.assertEqual(inspector.terminate_calls, 1)
        self.assertEqual(inspector.set_limit_calls, [2, 1], "the freeze is tightened to the smaller set")

    def test_membership_that_keeps_changing_is_refused_after_the_budget(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101], [101, 102], [101], [101, 102], [101]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("kept changing", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)

    def test_one_attempt_queries_membership_exactly_four_times(self) -> None:
        inspector = FakeJobInspector([[101, 102]])
        self.repair(inspector)
        self.assertEqual(inspector.pid_calls, 4, "two snapshots to validate, two to re-check")

    def test_an_empty_job_is_frozen_at_zero_and_still_terminated(self) -> None:
        inspector = FakeJobInspector([[]])
        self.assertEqual(self.repair(inspector), 0)
        self.assertEqual(inspector.set_limit_calls, [0])
        self.assertEqual(inspector.terminate_calls, 1)


class FreezeTests(unittest.TestCase):
    def repair(self, inspector, job=None):
        return recovery.repair_stale_job(job or make_job(), APPINFO_PID, reporting.Reporter(), inspector)

    def test_a_job_that_cannot_be_frozen_is_never_terminated(self) -> None:
        inspector = FakeJobInspector([[101, 102]], freeze_available=False)
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("cannot be frozen", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)
        self.assertEqual(inspector.set_limit_calls, [])

    def test_a_freeze_that_cannot_be_applied_is_never_terminated(self) -> None:
        inspector = FakeJobInspector([[101, 102]], set_limit_error=OSError(5, "Access is denied"))
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector)
        self.assertIn("could not be frozen", str(stop.exception))
        self.assertEqual(inspector.terminate_calls, 0)
        self.assertEqual(inspector.restore_calls, [], "nothing was applied, so nothing is restored")
        self.assertEqual(inspector.closed, [0xF00D], "the extra handle is always closed")

    def test_the_freeze_is_restored_when_a_later_query_fails(self) -> None:
        inspector = FailingInspector([[101, 102]], fail_pids_at=3)
        with self.assertRaises(RecoveryError):
            self.repair(inspector)
        self.assertEqual(len(inspector.restore_calls), 1)
        self.assertEqual(inspector.closed, [0xF00D])

    def test_the_freeze_is_restored_when_termination_fails(self) -> None:
        inspector = FakeJobInspector([[101, 102]], terminate_error=OSError(5, "Access is denied"))
        with self.assertRaises(OSError):
            self.repair(inspector)
        self.assertEqual(len(inspector.restore_calls), 1)
        self.assertEqual(inspector.closed, [0xF00D])

    def test_a_handle_without_terminate_access_is_refused_before_anything_else(self) -> None:
        inspector = FakeJobInspector([[101, 102]])
        with self.assertRaises(SafetyStop) as stop:
            self.repair(inspector, job=make_job(access=winapi.JOB_OBJECT_QUERY))
        self.assertIn("query/terminate access", str(stop.exception))
        self.assertEqual(inspector.duplicate_calls, 0)
        self.assertEqual(inspector.terminate_calls, 0)

    def test_the_probe_reports_availability_without_changing_anything(self) -> None:
        inspector = FakeJobInspector([[101, 102]])
        probe = recovery.probe_freeze(make_job(), inspector)
        self.assertTrue(probe["available"])
        self.assertEqual(inspector.set_limit_calls, [])
        self.assertEqual(inspector.terminate_calls, 0)
        self.assertEqual(inspector.closed, [0xF00D])

    def test_the_probe_reports_an_unavailable_freeze(self) -> None:
        inspector = FakeJobInspector([[101, 102]], freeze_available=False)
        probe = recovery.probe_freeze(make_job(), inspector)
        self.assertFalse(probe["available"])
        self.assertIn("denied", probe["error"])


class SelfCheckTests(unittest.TestCase):
    def test_the_shipped_self_check_runs_the_race_fixtures(self) -> None:
        reporter = reporting.Reporter()
        reporter.emit = lambda *args, **kwargs: reporter.lines.append(" ".join(str(a) for a in args))  # type: ignore[assignment]
        self.assertTrue(recovery.historical_self_check(reporter))
        self.assertTrue(any("race guards 5/5" in line for line in reporter.lines), reporter.lines)


if __name__ == "__main__":
    unittest.main()
