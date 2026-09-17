"""build.py: the two-stage build, the stage guard, the archive, and the smoke test.

The executables are simulated; what is under test is the orchestration that makes the
console build carry a true record of the windowed twin shipped with it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("claude_restart_build", ROOT / "build.py")
build = importlib.util.module_from_spec(_spec)
# ClaudeRestart.spec loads build.py exactly this way, including the sys.modules entry.
sys.modules[_spec.name] = build
_spec.loader.exec_module(build)


class SmokeTestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        for name in build.EXECUTABLES:
            (self.dist / name).write_bytes(b"")
        self.calls: list[list[str]] = []
        self.race_guards = "5/5"
        self.record = build.TwinRecord("ClaudeRestart-quiet.exe", "a" * 64, 7, "1.0.1")

    def fake_run(self, version_output: str = "ClaudeRestart 1.0.1", embedded: str | None = None):
        """Stand-in for build.run (the console exe): records calls, returns output."""

        def run(command, **kwargs):
            self.calls.append(command)
            stdout = ""
            if command[-1] == "--version":
                stdout = version_output + "\n"
            elif command[-1] == "--self-check":
                stdout = f"[SELF-CHECK] fixtures passed; race guards {self.race_guards}\n"
                (self.dist / "last-run.log").write_text("[SELF-CHECK] console\n", encoding="utf-8")
            elif command[-1] == "--print-embedded-twin":
                if embedded is None:
                    embedded_line = f"{self.record.name} {self.record.sha256} {self.record.size} {self.record.version}"
                else:
                    embedded_line = embedded
                stdout = f"[EMBEDDED TWIN] {embedded_line}\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        return run

    def fake_quiet(self, returncode: int = 0, write_log: bool = True, carries_record: bool = False):
        """Stand-in for subprocess.run (the windowed exe): no output, optional log."""

        def run(command, **kwargs):
            self.calls.append(command)
            if command[-1] == "--print-embedded-twin":
                text = "[EMBEDDED TWIN] a-record\n" if carries_record else "[EMBEDDED TWIN] none\n"
                (self.dist / "last-run.log").write_text(text, encoding="utf-8")
            elif write_log:
                (self.dist / "last-run.log").write_text("[SELF-CHECK] quiet ok\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, returncode)

        return run

    def smoke(self, *, record: build.TwinRecord | None = None, **kwargs):
        with mock.patch.object(build, "run", self.fake_run(**kwargs)), mock.patch.object(
            build.subprocess, "run", self.fake_quiet()
        ), mock.patch("builtins.print"):
            build.smoke_test(self.dist, "1.0.1", record)

    def test_both_executables_are_exercised(self) -> None:
        self.smoke(record=self.record)
        invoked = [(Path(c[0]).name, c[-1]) for c in self.calls]
        self.assertEqual(
            invoked,
            [
                ("ClaudeRestart.exe", "--version"),
                ("ClaudeRestart.exe", "--self-check"),
                ("ClaudeRestart.exe", "--print-embedded-twin"),
                ("ClaudeRestart-quiet.exe", "--self-check"),
                ("ClaudeRestart-quiet.exe", "--print-embedded-twin"),
            ],
        )
        self.assertFalse((self.dist / "last-run.log").exists(), "the smoke log is cleaned up")

    def test_a_console_build_carrying_the_wrong_twin_record_stops_the_build(self) -> None:
        with self.assertRaises(SystemExit) as stop:
            self.smoke(record=self.record, embedded="ClaudeRestart-quiet.exe " + "b" * 64 + " 7 1.0.1")
        self.assertIn("is not the twin that was built", str(stop.exception))

    def test_a_windowed_build_carrying_a_record_stops_the_build(self) -> None:
        with mock.patch.object(build, "run", self.fake_run()), mock.patch.object(
            build.subprocess, "run", self.fake_quiet(carries_record=True)
        ), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1", self.record)
        self.assertIn("carries a twin record", str(stop.exception))

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

    def test_a_self_check_that_fails_a_race_guard_stops_the_build(self) -> None:
        self.race_guards = "4/5"
        with self.assertRaises(SystemExit) as stop:
            self.smoke(record=self.record)
        self.assertIn("race guard", str(stop.exception))

    def test_version_mismatch_stops_the_build(self) -> None:
        with self.assertRaises(SystemExit) as stop:
            self.smoke(version_output="ClaudeRestart 9.9.9")
        self.assertIn("does not contain 1.0.1", str(stop.exception))
        self.assertEqual(len(self.calls), 1, "nothing runs after the version check fails")

    def test_missing_executable_stops_the_build(self) -> None:
        (self.dist / "ClaudeRestart-quiet.exe").unlink()
        with mock.patch.object(build, "run", self.fake_run()), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as stop:
                build.smoke_test(self.dist, "1.0.1")
        self.assertIn("did not produce ClaudeRestart-quiet.exe", str(stop.exception))

    def test_read_version_matches_the_module_constant(self) -> None:
        import clauderestart

        self.assertRegex(build.read_version(), r"^\d+\.\d+\.\d+$")
        # Without this the build could embed one version while the package reports another.
        self.assertEqual(build.read_version(), clauderestart.__version__)


class TwoStageBuildTests(unittest.TestCase):
    """The windowed twin is built first, its digest embedded, then the console build."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.dist = self.folder / "dist"
        self.dist.mkdir()
        self.twin_module = self.folder / "_twin.py"
        self.quiet_bytes = b"the windowed twin"
        self.stages: list[tuple[str, str | None]] = []
        self.enter = mock.patch.multiple(
            build, DIST=self.dist, TWIN_MODULE=self.twin_module
        )
        self.enter.start()
        self.addCleanup(self.enter.stop)

    def fake_pyinstaller(self, fail_console: bool = False):
        def run(command, **kwargs):
            target = (kwargs.get("env") or {}).get(build.BUILD_TARGET_ENV)
            record = build.read_twin_module()
            self.stages.append((target, record.sha256 if record else None))
            if target == "quiet":
                (self.dist / "ClaudeRestart-quiet.exe").write_bytes(self.quiet_bytes)
            elif target == "console":
                if fail_console:
                    raise subprocess.CalledProcessError(1, command)
                (self.dist / "ClaudeRestart.exe").write_bytes(b"the console build")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        return run

    def test_stages_run_in_order_with_the_record_written_between_them(self) -> None:
        with mock.patch.object(build, "run", self.fake_pyinstaller()), mock.patch("builtins.print"):
            record = build.build_executables("python", "1.0.3")
        self.assertEqual([stage for stage, _ in self.stages], ["quiet", "console"])
        self.assertIsNone(self.stages[0][1], "the windowed build must carry no record")
        self.assertEqual(self.stages[1][1], hashlib.sha256(self.quiet_bytes).hexdigest())
        self.assertEqual(record.sha256, hashlib.sha256(self.quiet_bytes).hexdigest())
        self.assertEqual(record.size, len(self.quiet_bytes))
        self.assertEqual(record.version, "1.0.3")
        self.assertIsNone(build.read_twin_module(), "the placeholder is restored after the build")

    def test_a_failed_console_stage_still_restores_the_placeholder(self) -> None:
        with mock.patch.object(build, "run", self.fake_pyinstaller(fail_console=True)), mock.patch("builtins.print"):
            with self.assertRaises(subprocess.CalledProcessError):
                build.build_executables("python", "1.0.3")
        self.assertIsNone(build.read_twin_module())

    def test_the_stage_guard_refuses_every_wrong_combination(self) -> None:
        build.write_twin_module(None)
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("", self.dist)
        self.assertIn(build.BUILD_TARGET_ENV, str(stop.exception))

        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("console", self.dist)
        self.assertIn("needs the record", str(stop.exception))

        real = build.TwinRecord("ClaudeRestart-quiet.exe", hashlib.sha256(self.quiet_bytes).hexdigest(), len(self.quiet_bytes), build.read_version())
        build.write_twin_module(real)
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("quiet", self.dist)
        self.assertIn("must not carry", str(stop.exception))

        stale = build.TwinRecord(real.name, real.sha256, real.size, "0.0.1")
        build.write_twin_module(stale)
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("console", self.dist)
        self.assertIn("0.0.1", str(stop.exception))

        build.write_twin_module(real)
        (self.dist / "ClaudeRestart-quiet.exe").write_bytes(b"different bytes")
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("console", self.dist)
        self.assertIn("does not match", str(stop.exception))

        same_length = b"THE WINDOWED TWIN"
        self.assertEqual(len(same_length), len(self.quiet_bytes))
        self.assertNotEqual(same_length, self.quiet_bytes)
        (self.dist / "ClaudeRestart-quiet.exe").write_bytes(same_length)
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("console", self.dist)
        self.assertIn("does not match", str(stop.exception))

        (self.dist / "ClaudeRestart-quiet.exe").unlink()
        with self.assertRaises(SystemExit) as stop:
            build.twin_record_for_target("console", self.dist)
        self.assertIn("no windowed twin", str(stop.exception))

        (self.dist / "ClaudeRestart-quiet.exe").write_bytes(self.quiet_bytes)
        self.assertEqual(build.twin_record_for_target("console", self.dist), real)

    def test_a_same_second_rewrite_of_equal_length_is_read_back_correctly(self) -> None:
        # The stages rewrite this file moments apart. Reading it through the import
        # machinery would hit a bytecode cache keyed on whole-second mtime plus size,
        # and these two records are deliberately the same length.
        first = build.TwinRecord("ClaudeRestart-quiet.exe", "a" * 64, 11, "1.0.2")
        second = build.TwinRecord("ClaudeRestart-quiet.exe", "b" * 64, 11, "0.0.1")
        build.write_twin_module(first)
        self.assertEqual(build.read_twin_module(), first)
        build.write_twin_module(second)
        self.assertEqual(build.read_twin_module(), second)
        build.write_twin_module(None)
        self.assertIsNone(build.read_twin_module())


class ArchiveAndManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.dist = self.folder / "dist"
        self.dist.mkdir()
        self.source_root = self.folder / "repo"
        for relative in build.RELEASE_FILES:
            path = self.source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"contents of {relative}\n", encoding="utf-8")
        for name in build.EXECUTABLES:
            (self.dist / name).write_bytes(f"binary {name}".encode())
        self.enter = mock.patch.multiple(build, DIST=self.dist, ROOT=self.source_root)
        self.enter.start()
        self.addCleanup(self.enter.stop)

    def test_the_zip_is_byte_identical_when_only_timestamps_differ(self) -> None:
        first = self.dist / "first.zip"
        build.build_zip(first, 1700000000)
        digest_first = hashlib.sha256(first.read_bytes()).hexdigest()
        for relative in build.RELEASE_FILES:
            path = self.source_root / relative
            os_stat = path.stat()
            import os

            os.utime(path, (os_stat.st_atime + 86400, os_stat.st_mtime + 86400))
        second = self.dist / "second.zip"
        build.build_zip(second, 1700000000)
        self.assertEqual(hashlib.sha256(second.read_bytes()).hexdigest(), digest_first)

    def test_the_manifest_lists_every_release_asset_with_its_digest(self) -> None:
        archive = self.dist / build.payload.release_zip_name("1.0.3")
        build.build_zip(archive, 1700000000)
        # Call the build's own writer: a copy of its code here could never catch a change to it.
        sums, lines = build.write_checksums(self.dist, (*build.EXECUTABLES, archive.name))
        record = build.TwinRecord("ClaudeRestart-quiet.exe", build.sha256(self.dist / "ClaudeRestart-quiet.exe"), 1, "1.0.3")

        manifest_path = build.write_release_manifest(self.dist, "1.0.3", record)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], "1.0.3")
        self.assertEqual(manifest["tag"], "v1.0.3")
        names = [asset["name"] for asset in manifest["assets"]]
        self.assertEqual(names, list(build.payload.release_asset_names("1.0.3")))
        by_name = {asset["name"]: asset for asset in manifest["assets"]}
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(by_name[name]["sha256"], digest, name)
        self.assertEqual(by_name[build.payload.CHECKSUMS_NAME]["sha256"], build.sha256(sums))
        self.assertEqual(len(manifest["assets"]), 4)

    def test_the_checksum_file_is_readable_by_sha256sum_everywhere(self) -> None:
        # sha256sum -c on Linux or macOS reads a carriage return as part of each file name, so a
        # checksum file with Windows line endings fails for anyone checking a download there.
        sums, lines = build.write_checksums(self.dist, tuple(build.EXECUTABLES))
        data = sums.read_bytes()
        self.assertNotIn(b"\r", data)
        self.assertEqual(data.decode("utf-8").splitlines(), lines)
        for line in lines:
            self.assertRegex(line, r"^[0-9a-f]{64}  [^ ]")

    def test_the_manifest_refuses_to_describe_a_missing_asset(self) -> None:
        record = build.TwinRecord("ClaudeRestart-quiet.exe", "a" * 64, 1, "1.0.3")
        with self.assertRaises(SystemExit) as stop:
            build.write_release_manifest(self.dist, "1.0.3", record)
        self.assertIn("is missing", str(stop.exception))


if __name__ == "__main__":
    unittest.main()
