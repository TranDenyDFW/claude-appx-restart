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
        # "Nothing was changed" has to be true of the folder as well. A staged payload left
        # behind is a change, and it is the entire release sitting in Program Files.
        leftovers = sorted(path.name for path in install.versions_dir(self.root).iterdir())
        self.assertEqual(leftovers, [first.name])

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


@unittest.skipUnless(sys.platform == "win32", "these verifications read through file handles")
class StagedAndCommittedVerificationTests(unittest.TestCase):
    """The staged and committed checks must be able to refuse.

    Every behaviour below could be deleted with the whole suite green, because no test ever
    put a staged or committed folder into the state the check exists to catch. The install
    tests only ever exercise the path where everything is already correct.
    """

    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve() / f"{VERSION}-abcdef12"
        self.folder.mkdir(parents=True)
        self.quiet = self.folder / payload.QUIET_EXE_NAME
        self.quiet.write_bytes(QUIET_BYTES)
        self.twin_sha = hashlib.sha256(QUIET_BYTES).hexdigest()
        self.security = support.FakeFileSecurity()

    def manifest(self) -> install.InstallManifest:
        digest, size = install.file_digest(self.quiet)
        return install.InstallManifest(
            VERSION,
            "abcdef12",
            {payload.QUIET_EXE_NAME: {"sha256": digest, "size": size}},
            {"sha256": self.twin_sha, "size": size, "version": VERSION},
        )

    def verify_staged(self, manifest: install.InstallManifest | None = None, twin_sha: str | None = None) -> None:
        install._verify_staged(
            self.folder, manifest or self.manifest(), self.security, twin_sha or self.twin_sha
        )

    def verify_committed(self, manifest: install.InstallManifest | None = None, twin_sha: str | None = None) -> None:
        locked = winapi.open_locked(self.quiet)
        try:
            install._verify_committed(
                self.folder, locked, manifest or self.manifest(), self.security, twin_sha or self.twin_sha
            )
        finally:
            locked.close()

    def test_a_correct_staged_folder_passes(self) -> None:
        self.verify_staged()

    def test_a_correct_committed_folder_passes(self) -> None:
        self.verify_committed()

    def test_a_file_that_is_not_part_of_the_release_stops_the_install(self) -> None:
        (self.folder / "extra.dll").write_bytes(b"planted beside the staged payload")
        with self.assertRaises(SafetyStop) as stop:
            self.verify_staged()
        self.assertIn("not part of this release", str(stop.exception))

    def test_a_staged_twin_that_is_not_the_authenticated_one_stops_the_install(self) -> None:
        with self.assertRaises(SafetyStop) as stop:
            self.verify_staged(twin_sha="0" * 64)
        self.assertIn("not the one this build was made with", str(stop.exception))

    def test_a_committed_twin_that_is_not_the_authenticated_one_is_refused(self) -> None:
        with self.assertRaises(SafetyStop) as stop:
            self.verify_committed(twin_sha="0" * 64)
        self.assertIn("not the authenticated one", str(stop.exception))

    def test_a_committed_file_whose_contents_changed_is_refused(self) -> None:
        # Same length as the original, so only the digest comparison can catch it.
        manifest = self.manifest()
        extra = self.folder / "README.md"
        extra.write_text("original\n", encoding="utf-8")
        digest, size = install.file_digest(extra)
        manifest.files["README.md"] = {"sha256": digest, "size": size}
        extra.write_text("modified\n", encoding="utf-8")
        self.assertEqual(size, extra.stat().st_size)
        with self.assertRaises(SafetyStop) as stop:
            self.verify_committed(manifest)
        self.assertIn("did not verify", str(stop.exception))

    def test_the_manifest_reports_a_change_of_the_same_length(self) -> None:
        # Without this the size comparison decides every case and the digest half is dead
        # weight: an installed file can be replaced byte for byte and still verify.
        manifest = self.manifest()
        self.assertEqual(manifest.verify(self.folder), [])
        same_length = bytes(len(QUIET_BYTES))
        self.assertNotEqual(same_length, QUIET_BYTES)
        self.quiet.write_bytes(same_length)
        problems = manifest.verify(self.folder)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("does not match what was installed", problems[0])


if __name__ == "__main__":
    unittest.main()
