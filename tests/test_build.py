"""Tests for build.py's executable smoke test, with the executables simulated."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("claude_restart_build", ROOT / "build.py")
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


class SmokeTestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        for name in build.EXECUTABLES:
            (self.dist / name).write_bytes(b"")
        self.calls: list[list[str]] = []

    def fake_run(self, version_output: str = "ClaudeRestart 1.0.1"):
        """Stand-in for build.run (the console exe): records calls, returns the version."""

        def run(command, **kwargs):
            self.calls.append(command)
            if command[-1] == "--self-check":
                (self.dist / "last-run.log").write_text("[SELF-CHECK] console\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout=version_output + "\n", stderr="")

        return run

    def fake_quiet(self, returncode: int = 0, write_log: bool = True):
        """Stand-in for subprocess.run (the windowed exe): no output, optional log."""

        def run(command, **kwargs):
            self.calls.append(command)
            if write_log:
                (self.dist / "last-run.log").write_text("[SELF-CHECK] quiet ok\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, returncode)

        return run

    def test_both_executables_are_exercised(self) -> None:
        with mock.patch.object(build, "run", self.fake_run()), mock.patch.object(
            build.subprocess, "run", self.fake_quiet()
        ), mock.patch("builtins.print"):
            build.smoke_test(self.dist, "1.0.1")
        invoked = [(Path(c[0]).name, c[-1]) for c in self.calls]
        self.assertEqual(
            invoked,
            [("ClaudeRestart.exe", "--version"), ("ClaudeRestart.exe", "--self-check"), ("ClaudeRestart-quiet.exe", "--self-check")],
        )
        self.assertFalse((self.dist / "last-run.log").exists(), "the smoke log is cleaned up")

    def test_quiet_executable_failure_stops_the_build(self) -> None:
        with mock.patch.object(build, "run", self.fake_run()), mock.patch.object(
            build.subprocess, "run", self.fake_quiet(returncode=3)
        ), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1")
        self.assertIn("ClaudeRestart-quiet.exe --self-check exited 3", str(stop.exception))

    def test_quiet_executable_must_write_its_log(self) -> None:
        with mock.patch.object(build, "run", self.fake_run()), mock.patch.object(
            build.subprocess, "run", self.fake_quiet(write_log=False)
        ), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1")
        self.assertIn("did not write last-run.log", str(stop.exception))

    def test_version_mismatch_stops_the_build(self) -> None:
        with mock.patch.object(build, "run", self.fake_run("ClaudeRestart 9.9.9")), mock.patch.object(
            build.subprocess, "run", self.fake_quiet()
        ), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1")
        self.assertIn("does not contain 1.0.1", str(stop.exception))
        self.assertEqual(len(self.calls), 1, "nothing runs after the version check fails")

    def test_missing_executable_stops_the_build(self) -> None:
        (self.dist / "ClaudeRestart-quiet.exe").unlink()
        with mock.patch.object(build, "run", self.fake_run()), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1")
        self.assertIn("did not produce ClaudeRestart-quiet.exe", str(stop.exception))

    def test_read_version_matches_the_module_constant(self) -> None:
        self.assertRegex(build.read_version(), r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
