"""Command-line hardening: exit codes, console-less runs, and the version flag."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

import clauderestart  # noqa: E402
from clauderestart import cli, payload  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
