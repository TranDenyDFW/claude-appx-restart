"""What a run reports, in order, for a repair and for a read-only scan.

The counts in these lines are what the manual gate reads, so they come from the
validated set rather than from the numbers discovery happened to see first.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import cli, package as package_module, recovery, reporting, winapi  # noqa: E402
from clauderestart.fakes import FakeJobInspector  # noqa: E402


JOB_NAME = r"\Container_Claude_1.0.0.0_x64__pzs8sxrjxfjjc-S-1-5-21-1-2-3-1001"
FULL_ACCESS = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE


def package() -> package_module.PackageInfo:
    return package_module.PackageInfo(
        "Claude",
        "1.52386.6.0",
        "Claude_1.52386.6.0_x64__pzs8sxrjxfjjc",
        package_module.EXPECTED_PACKAGE_FAMILY,
        r"C:\Program Files\WindowsApps\fixture",
        "Claude",
        "S-1-5-21-1111111111-2222222222-3333333333-1001",
    )


def job(name: str = JOB_NAME, pids=(101, 102)) -> recovery.JobRecord:
    return recovery.JobRecord(9, 9, 0x1234, FULL_ACCESS, name, list(pids))


class RunReportingTests(unittest.TestCase):
    def run_cli(self, argv: list[str], inspector: FakeJobInspector, *, stale=None, current=None):
        stale = [job()] if stale is None else stale
        current = [] if current is None else current
        args = cli.build_parser().parse_args(argv)
        reporter = reporting.Reporter()
        with mock.patch.object(cli, "get_claude_package", return_value=package()), mock.patch.object(
            cli.recovery, "get_appinfo_pid", return_value=4242
        ), mock.patch.object(cli.recovery, "discover_claude_jobs", return_value=stale + current), mock.patch.object(
            cli.recovery, "classify_jobs", return_value=(stale, current)
        ), mock.patch.object(cli.recovery, "process_details", return_value=[]), mock.patch.object(
            cli.recovery, "close_job_records"
        ), mock.patch.object(cli.recovery, "launch_and_verify", return_value=True), mock.patch.object(
            cli.recovery, "WindowsJobInspector", return_value=inspector
        ):
            code = cli.run(args, reporter)
        return code, [line.split("]")[0].lstrip("[") for line in reporter.lines], reporter.lines

    def test_a_clean_repair_reports_each_step_in_order(self) -> None:
        inspector = FakeJobInspector([[101, 102]])
        code, states, lines = self.run_cli(["--yes"], inspector)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(states, ["PACKAGE", "SCAN", "STALE", "REVALIDATED", "FREEZE", "CLOSED"])
        self.assertIn("2 live member(s)", lines[3])
        self.assertIn("2 validated member(s)", lines[4])
        self.assertIn("its 2 member(s)", lines[5])
        self.assertEqual(inspector.terminate_calls, 1)

    def test_a_member_that_exits_is_reported_with_the_smaller_count(self) -> None:
        inspector = FakeJobInspector([[101, 102], [101]])
        code, states, lines = self.run_cli(["--yes"], inspector)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(states, ["PACKAGE", "SCAN", "STALE", "NOTE", "REVALIDATED", "FREEZE", "CLOSED"])
        self.assertIn("1 live member(s)", lines[4])
        self.assertIn("its 1 member(s)", lines[6], "the count comes from the validated set")

    def test_a_scan_probes_the_freeze_and_terminates_nothing(self) -> None:
        inspector = FakeJobInspector([[101, 102]])
        code, states, lines = self.run_cli(["--scan"], inspector, current=[job(name=JOB_NAME + "-current")])
        self.assertEqual(code, cli.EXIT_STALE_FOUND)
        self.assertEqual(states, ["PACKAGE", "SCAN", "CURRENT", "STALE", "FREEZE", "FREEZE", "DRY-RUN"])
        self.assertIn("CURRENT", lines[4])
        self.assertIn("STALE", lines[5])
        self.assertIn("freeze available", lines[4])
        self.assertEqual(inspector.terminate_calls, 0)
        self.assertEqual(inspector.set_limit_calls, [])

    def test_a_scan_reports_a_freeze_that_is_unavailable(self) -> None:
        inspector = FakeJobInspector([[101, 102]], freeze_available=False)
        code, _states, lines = self.run_cli(["--scan"], inspector)
        self.assertEqual(code, cli.EXIT_STALE_FOUND)
        self.assertTrue(any("freeze unavailable" in line for line in lines), lines)
        self.assertEqual(inspector.terminate_calls, 0)


if __name__ == "__main__":
    unittest.main()
