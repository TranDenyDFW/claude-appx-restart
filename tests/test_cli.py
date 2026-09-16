"""Command-line hardening: exit codes, console-less runs, and refusal ordering."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

import clauderestart  # noqa: E402
from clauderestart import cli, package as package_module, payload, reporting  # noqa: E402
from clauderestart.errors import SafetyStop  # noqa: E402


class MainHardeningTests(unittest.TestCase):
    def test_stdin_none_is_not_interactive(self) -> None:
        with mock.patch.object(sys, "stdin", None):
            self.assertFalse(cli._stdin_is_interactive())

    def test_pause_without_a_console_returns_quietly(self) -> None:
        with mock.patch.object(sys, "stdin", None):
            cli._pause()

    def test_event_triggered_exit_codes_stay_zero_unless_internal_error(self) -> None:
        for code in (cli.EXIT_OK, cli.EXIT_ERROR, cli.EXIT_SAFETY_STOP, cli.EXIT_STALE_FOUND):
            self.assertEqual(cli.event_triggered_exit_code(code), cli.EXIT_OK)
        self.assertEqual(cli.event_triggered_exit_code(cli.EXIT_INTERNAL_ERROR), cli.EXIT_INTERNAL_ERROR)

    def test_version_constant_is_semver(self) -> None:
        self.assertRegex(clauderestart.__version__, r"^\d+\.\d+\.\d+$")

    @unittest.skipUnless(sys.platform == "win32", "the CLI only runs on Windows")
    def test_version_flag_prints_the_version(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(payload.SOURCE_ENTRY), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(clauderestart.__version__, completed.stdout)


class UnknownIdentityRunTests(unittest.TestCase):
    """An unknown application id must stop the run before anything is terminated."""

    def unknown(self) -> package_module.PackageInfo:
        return package_module.PackageInfo(
            "Claude",
            "1.52386.6.0",
            "Claude_1.52386.6.0_x64__pzs8sxrjxfjjc",
            package_module.EXPECTED_PACKAGE_FAMILY,
            r"C:\Program Files\WindowsApps\fixture",
            None,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "the package manifest could not be read: access is denied",
        )

    def run_with_unknown_identity(self, argv: list[str]) -> tuple[reporting.Reporter, dict[str, mock.Mock]]:
        args = cli.build_parser().parse_args(argv)
        reporter = reporting.Reporter()
        with mock.patch.object(cli, "get_claude_package", return_value=self.unknown()), mock.patch.object(
            cli.recovery, "get_appinfo_pid", return_value=0
        ) as appinfo, mock.patch.object(cli.recovery, "repair_stale_job") as terminate, mock.patch.object(
            cli.recovery, "launch_and_verify", return_value=True
        ) as launch, mock.patch.object(cli.events, "auto_recovery_events", return_value=[]) as events_query:
            calls = {
                "appinfo": appinfo,
                "terminate": terminate,
                "launch": launch,
                "events": events_query,
            }
            try:
                self.outcome: object = cli.run(args, reporter)
            except SafetyStop as exc:
                self.outcome = exc
        return reporter, calls

    def assert_refused(self, reporter: reporting.Reporter, calls: dict[str, mock.Mock]) -> None:
        self.assertIsInstance(self.outcome, SafetyStop)
        self.assertIn("application id unknown", str(self.outcome))
        calls["appinfo"].assert_not_called()
        calls["terminate"].assert_not_called()
        calls["launch"].assert_not_called()
        self.assertTrue(any(line.startswith("[WARN]") for line in reporter.lines), reporter.lines)

    def test_manual_run_refuses_before_touching_jobs(self) -> None:
        reporter, calls = self.run_with_unknown_identity(["--yes"])
        self.assert_refused(reporter, calls)

    def test_event_triggered_run_refuses_and_reports_zero_to_the_scheduler(self) -> None:
        reporter, calls = self.run_with_unknown_identity(["--event-triggered", "--yes"])
        self.assert_refused(reporter, calls)
        calls["events"].assert_not_called()
        # main maps a safety stop to 0 for an event-triggered run, with the reason logged.
        self.assertEqual(cli.event_triggered_exit_code(cli.EXIT_SAFETY_STOP), cli.EXIT_OK)

    def test_scan_stays_read_only_and_still_reports(self) -> None:
        reporter, calls = self.run_with_unknown_identity(["--scan"])
        self.assertEqual(self.outcome, cli.EXIT_OK)
        calls["appinfo"].assert_called_once()
        calls["terminate"].assert_not_called()
        calls["launch"].assert_not_called()
        self.assertTrue(any(line.startswith("[WARN]") for line in reporter.lines), reporter.lines)


if __name__ == "__main__":
    unittest.main()
