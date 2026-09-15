"""Installing a version is all or nothing, and the live task is never overwritten.

Every failure case asserts the same two things: the previously installed version is
byte for byte what it was, and the scheduled task is exactly what it was. A new version
is only ever reached by renaming a fully verified folder into place.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

import clauderestart  # noqa: E402
from clauderestart import install, package as package_module, payload, reporting, task as task_module  # noqa: E402
from clauderestart import twin as twin_module, winapi  # noqa: E402
from clauderestart.errors import RecoveryError, SafetyStop  # noqa: E402


CONSOLE_BYTES = b"the console executable"
QUIET_BYTES = b"the windowed executable"
VERSION = clauderestart.__version__


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


@unittest.skipUnless(sys.platform == "win32", "installing is a Windows operation")
class TransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()

        # The extracted download: the running console executable and its twin.
        self.download = self.base / "Downloads" / "ClaudeRestart"
        (self.download / "docs").mkdir(parents=True)
        self.console_path = self.download / payload.CONSOLE_EXE_NAME
        self.console_path.write_bytes(CONSOLE_BYTES)
        self.quiet_path = self.download / payload.QUIET_EXE_NAME
        self.quiet_path.write_bytes(QUIET_BYTES)
        for relative in payload.SUPPORT_FILES:
            path = self.download / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"contents of {relative}\n", encoding="utf-8")
        (self.download / "unrelated.txt").write_text("not part of the release", encoding="utf-8")

        self.root = self.base / "Program Files" / payload.INSTALL_DIRNAME
        self.root.parent.mkdir(parents=True)
        self.reporter = reporting.Reporter()
        self.security = support.FakeFileSecurity()

        self.frozen = support.frozen_at(self.console_path)
        self.frozen.__enter__()
        self.addCleanup(self.frozen.close)
        self.console_lock = winapi.open_locked(self.console_path)
        self.addCleanup(self.console_lock.close)
        patcher = mock.patch.object(twin_module, "console_lock", return_value=self.console_lock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def authenticated(self) -> twin_module.AuthenticatedTwin:
        locked = winapi.open_locked(self.quiet_path)
        self.addCleanup(locked.close)
        return twin_module.AuthenticatedTwin(
            locked=locked,
            path=self.quiet_path,
            sha256=hashlib.sha256(QUIET_BYTES).hexdigest(),
            size=len(QUIET_BYTES),
        )

    def install(self, tasks: support.FakeTaskBackend | None = None, **kwargs) -> Path:
        tasks = tasks if tasks is not None else support.FakeTaskBackend()
        self.tasks = tasks
        return install.install_versioned(
            self.reporter,
            self.authenticated(),
            package(),
            backend=self.security,
            tasks=tasks,
            root=self.root,
            **kwargs,
        )

    def seed_previous_version(self, version: str = VERSION) -> Path:
        """Install once, so later cases have a real previous version to protect."""
        folder = self.install()
        self.reporter = reporting.Reporter()
        return folder

    def test_a_clean_install_produces_one_verified_version_and_one_task(self) -> None:
        folder = self.install()
        self.assertTrue(folder.is_dir())
        self.assertEqual(folder.parent, install.versions_dir(self.root))
        self.assertTrue(folder.name.startswith(VERSION + "-"), folder.name)
        manifest = install.InstallManifest.read(folder)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.verify(folder), [])
        self.assertEqual((folder / payload.QUIET_EXE_NAME).read_bytes(), QUIET_BYTES)
        self.assertEqual((folder / payload.CONSOLE_EXE_NAME).read_bytes(), CONSOLE_BYTES)
        self.assertFalse((folder / "unrelated.txt").exists(), "only the release payload is installed")
        self.assertEqual(len(self.tasks.registered), 1)
        status = self.tasks.automation_task_status()
        self.assertEqual(
            task_module.task_command_path(status["Execute"]), folder / payload.QUIET_EXE_NAME
        )
        self.assertEqual(status["Arguments"], task_module.TASK_ARGUMENTS)
        states = [line.split("]")[0].lstrip("[") for line in self.reporter.lines]
        self.assertIn("COPIED", states)
        self.assertIn("INSTALLED", states)

    def test_a_second_install_moves_the_task_and_removes_the_old_version(self) -> None:
        first = self.seed_previous_version()
        second = self.install()
        self.assertNotEqual(first, second)
        self.assertTrue(second.is_dir())
        self.assertFalse(first.exists(), "the previous version is cleaned up once nothing uses it")
        status = self.tasks.automation_task_status()
        self.assertEqual(
            task_module.task_command_path(status["Execute"]), second / payload.QUIET_EXE_NAME
        )

    def test_a_failure_while_staging_leaves_the_previous_install_untouched(self) -> None:
        first = self.seed_previous_version()
        before_tree = support.tree_hash(first)
        before_status = self.tasks.automation_task_status()
        tasks = support.FakeTaskBackend(status=before_status, xml="<Task>previous</Task>")
        with mock.patch.object(install, "_copy_path", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.install(tasks)
        self.assertEqual(support.tree_hash(first), before_tree)
        self.assertEqual(tasks.registered, [])
        staging = [path for path in install.versions_dir(self.root).iterdir() if payload.STAGING_SUFFIX in path.name]
        self.assertEqual(staging, [], "a failed staging folder is removed")

    def test_a_failed_rename_reports_a_retry_and_changes_nothing(self) -> None:
        first = self.seed_previous_version()
        before_tree = support.tree_hash(first)
        tasks = support.FakeTaskBackend(status=self.tasks.automation_task_status(), xml="<Task>previous</Task>")
        with mock.patch.object(install.os, "rename", side_effect=PermissionError("in use")):
            with self.assertRaises(RecoveryError) as stop:
                self.install(tasks)
        self.assertIn("wait a minute", str(stop.exception))
        self.assertEqual(tasks.registered, [])
        self.assertEqual(support.tree_hash(first), before_tree)

    def test_a_version_that_fails_its_final_check_is_set_aside_and_no_task_is_registered(self) -> None:
        # The verdict must pass while staging and fail after the commit, otherwise the
        # install stops earlier and this never reaches the branch under test. The phase
        # is read from the path: a staging folder carries the staging suffix.
        class FailsAfterCommit(support.FakeFileSecurity):
            def verify_child(self, locked):
                super().verify_child(locked)
                if payload.STAGING_SUFFIX in str(locked.path):
                    return support.AclReport(True, "S-1-5-32-544", [], [])
                return support.AclReport(False, "S-1-5-21-1-2-3-1001", ["the file is not inherited"], [])

        self.security = FailsAfterCommit()
        tasks = support.FakeTaskBackend()
        with self.assertRaises(SafetyStop) as stop:
            self.install(tasks)
        self.assertIn("unexpected permissions", str(stop.exception))
        self.assertEqual(tasks.registered, [])
        broken = [path.name for path in install.versions_dir(self.root).iterdir()]
        self.assertTrue(any(name.endswith(payload.BROKEN_SUFFIX) for name in broken), broken)

    def test_a_registration_failure_restores_the_previous_task_definition(self) -> None:
        self.seed_previous_version()
        previous_xml = "<Task>the previous definition</Task>"
        tasks = support.FakeTaskBackend(
            status=self.tasks.automation_task_status(),
            xml=previous_xml,
            register_error=RecoveryError("schtasks refused the definition"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.registered[-1], previous_xml, "the exact previous definition is put back")
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)

    def test_a_registration_failure_with_no_previous_task_removes_the_new_one(self) -> None:
        tasks = support.FakeTaskBackend(register_error=RecoveryError("schtasks refused the definition"))
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.deleted, 1)

    def test_a_task_that_verifies_wrong_is_rolled_back(self) -> None:
        self.seed_previous_version()
        previous_xml = "<Task>the previous definition</Task>"
        tasks = support.FakeTaskBackend(
            status=self.tasks.automation_task_status(),
            xml=previous_xml,
            status_override={"MultipleInstances": "Parallel"},
        )
        with self.assertRaises(SafetyStop) as stop:
            self.install(tasks)
        self.assertIn("MultipleInstances", str(stop.exception))
        self.assertEqual(tasks.registered[-1], previous_xml)

    def test_an_export_failure_stops_before_anything_is_staged(self) -> None:
        first = self.seed_previous_version()
        before_tree = support.tree_hash(first)
        tasks = support.FakeTaskBackend(
            status=self.tasks.automation_task_status(),
            export_error=RecoveryError("Could not capture the existing task for rollback"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.registered, [])
        self.assertEqual(support.tree_hash(first), before_tree)
        staging = [path for path in install.versions_dir(self.root).iterdir() if payload.STAGING_SUFFIX in path.name]
        self.assertEqual(staging, [])

    def test_an_older_installer_refuses_to_replace_a_newer_version(self) -> None:
        newer = install.versions_dir(self.root)
        newer.mkdir(parents=True, exist_ok=True)
        folder = newer / "99.0.0-abcdef12"
        folder.mkdir()
        (folder / payload.QUIET_EXE_NAME).write_bytes(QUIET_BYTES)
        install.InstallManifest("99.0.0", "abcdef12", {}, {}).write(folder)
        status = support.FakeTaskBackend.status_from_xml(
            task_module.build_task_xml(
                folder / payload.QUIET_EXE_NAME, task_module.TASK_ARGUMENTS, package().user_sid, folder
            )
        )
        tasks = support.FakeTaskBackend(status=status, xml="<Task>the newer definition</Task>")
        with self.assertRaises(SafetyStop) as stop:
            self.install(tasks)
        self.assertIn("99.0.0", str(stop.exception))
        self.assertEqual(tasks.registered, [])

        allowed = support.FakeTaskBackend(status=status, xml="<Task>the newer definition</Task>")
        self.reporter = reporting.Reporter()
        self.install(allowed, allow_downgrade=True)
        self.assertEqual(len(allowed.registered), 1)

    def test_an_upgrade_from_a_source_task_registers_the_versioned_executable(self) -> None:
        source_xml = task_module.build_task_xml(
            Path(r"C:\Python314\pythonw.exe"),
            '"C:\\Users\\Example\\claude_restart.py" ' + task_module.TASK_ARGUMENTS,
            package().user_sid,
            Path(r"C:\Users\Example"),
        )
        tasks = support.FakeTaskBackend(
            status=support.FakeTaskBackend.status_from_xml(source_xml), xml=source_xml
        )
        folder = self.install(tasks)
        self.assertEqual(
            task_module.task_command_path(tasks.automation_task_status()["Execute"]),
            folder / payload.QUIET_EXE_NAME,
        )
        self.assertEqual(tasks.exported, 1, "the source definition is captured before it is replaced")

    def test_a_forced_failure_restores_the_exact_source_task_definition(self) -> None:
        source_xml = task_module.build_task_xml(
            Path(r"C:\Python314\pythonw.exe"),
            '"C:\\Users\\Example\\claude_restart.py" ' + task_module.TASK_ARGUMENTS,
            package().user_sid,
            Path(r"C:\Users\Example"),
        )
        tasks = support.FakeTaskBackend(
            status=support.FakeTaskBackend.status_from_xml(source_xml),
            xml=source_xml,
            register_error=RecoveryError("schtasks refused the definition"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.registered[-1], source_xml)

    def test_an_upgrade_from_the_flat_layout_removes_the_old_files(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "docs").mkdir()
        for relative in payload.LEGACY_ROOT_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"old flat install")
        keep = self.root / "notes-from-the-user.txt"
        keep.write_text("mine", encoding="utf-8")
        folder = self.install()
        self.assertTrue(folder.is_dir())
        self.assertFalse((self.root / payload.QUIET_EXE_NAME).exists())
        self.assertFalse((self.root / "docs").exists(), "the empty docs folder goes too")
        self.assertTrue(keep.is_file(), "files the installer never placed are kept")


if __name__ == "__main__":
    unittest.main()
