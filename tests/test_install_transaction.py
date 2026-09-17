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
        # Every authenticated twin holds the file open. A test that tampers with the twin
        # must release them first, because that lock denies exactly this.
        self.twin_locks: list[winapi.LockedFile] = []

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
        self.twin_locks.append(locked)
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

    def test_a_twin_failure_leaves_an_existing_install_and_its_task_untouched(self) -> None:
        """The review's own acceptance case: a bad twin over a working installation."""
        from clauderestart import cli

        first = self.seed_previous_version()
        before_tree = support.tree_hash(first)
        registered_before = len(self.tasks.registered)
        # The install held the twin open, and that lock denies a write, so release it first.
        for lock in self.twin_locks:
            lock.close()
        # Same length as the good twin, so only the digest comparison can refuse it.
        self.quiet_path.write_bytes(bytes(len(QUIET_BYTES)))
        record = twin_module.EmbeddedTwin(
            name=payload.QUIET_EXE_NAME,
            sha256=hashlib.sha256(QUIET_BYTES).hexdigest(),
            size=len(QUIET_BYTES),
            version=VERSION,
        )
        with mock.patch.object(twin_module, "load_embedded_twin", return_value=record), mock.patch.object(
            cli, "get_claude_package", return_value=package()
        ), mock.patch.object(install, "install_versioned") as installer, mock.patch.object(
            cli.task, "register_task_xml"
        ) as register, mock.patch.object(cli.task, "delete_task") as delete:
            with self.assertRaises(SafetyStop) as stop:
                cli.install_auto_recovery(self.reporter)
        self.assertIn("is not the windowed twin this build was made with", str(stop.exception))
        installer.assert_not_called()
        register.assert_not_called()
        delete.assert_not_called()
        self.assertEqual(support.tree_hash(first), before_tree)
        self.assertEqual(len(self.tasks.registered), registered_before)

    def test_the_running_version_is_left_in_place_with_a_retry(self) -> None:
        first = self.seed_previous_version()
        # Pretend this process is running out of the previous version folder, which is what
        # happens when a recovery is under way while the installer runs.
        with mock.patch.object(install, "app_entry", return_value=first / payload.CONSOLE_EXE_NAME):
            second = self.install()
        self.assertTrue(first.is_dir(), "the version running now must survive the cleanup")
        self.assertTrue(second.is_dir())
        retries = [line for line in self.reporter.lines if line.startswith("[RETRY]")]
        self.assertEqual(len(retries), 1, self.reporter.lines)
        self.assertIn(first.name, retries[0])

    def test_a_log_beside_a_version_goes_with_that_version(self) -> None:
        first = self.seed_previous_version()
        (first / payload.LOG_FILE_NAME).write_text("[OK] a previous run\n", encoding="utf-8")
        self.install()
        self.assertFalse(first.exists(), "the folder and the log it holds are both removed")

    def test_status_reports_each_version_and_notices_a_changed_file(self) -> None:
        folder = self.seed_previous_version()
        reporter = reporting.Reporter()
        install.installed_state(reporter, self.root)
        versions = [line for line in reporter.lines if line.startswith("[VERSION]")]
        self.assertEqual(len(versions), 1, reporter.lines)
        self.assertIn(folder.name, versions[0])
        self.assertIn("verified", versions[0])

        # Replace an installed file with different bytes of the same length, which only the
        # digest comparison can notice.
        installed = folder / payload.QUIET_EXE_NAME
        installed.write_bytes(bytes(len(QUIET_BYTES)))
        reporter = reporting.Reporter()
        install.installed_state(reporter, self.root)
        versions = [line for line in reporter.lines if line.startswith("[VERSION]")]
        self.assertEqual(len(versions), 1, reporter.lines)
        self.assertIn("does not match what was installed", versions[0])

    def test_status_says_so_when_nothing_is_installed(self) -> None:
        reporter = reporting.Reporter()
        install.installed_state(reporter, self.root / "absent")
        self.assertEqual(len(reporter.lines), 1, reporter.lines)
        self.assertIn("not installed", reporter.lines[0])

    def test_a_task_naming_the_right_path_but_a_different_file_is_refused(self) -> None:
        """The handle identity check, which the name comparison cannot stand in for.

        A task action can name exactly the right path while the file at that path is not the
        one that was just verified. Comparing the paths sees nothing wrong. Only comparing the
        open handles does, and that is the check the documentation promises by name.
        """
        folder = self.seed_previous_version()
        decoy = self.base / "decoy.exe"
        decoy.write_bytes(b"a different file entirely")
        installed = folder / payload.QUIET_EXE_NAME
        locked = winapi.open_locked(decoy)
        self.addCleanup(locked.close)
        tasks = support.FakeTaskBackend()
        with self.assertRaises(SafetyStop) as stop:
            install._register_and_verify(
                self.reporter, tasks, installed, package(), folder, None, False, locked
            )
        self.assertIn("runs a different file from the one installed", str(stop.exception))
        self.assertEqual(tasks.deleted, 1, "a task that cannot be verified is taken back out")

    def test_a_staging_name_that_already_exists_is_a_safety_stop(self) -> None:
        # The identifier is random, so a collision means something else put that folder there.
        # It is not used and not deleted, and the run reports that nothing was changed.
        identifier = "abcdef12"
        versions = install.versions_dir(self.root)
        versions.mkdir(parents=True)
        staging = versions / f"{VERSION}{payload.STAGING_SUFFIX}-{identifier}"
        staging.mkdir()
        planted = staging / "planted.txt"
        planted.write_text("a file this installer never wrote", encoding="utf-8")
        tasks = support.FakeTaskBackend()
        with mock.patch.object(install.secrets, "token_hex", return_value=identifier):
            with self.assertRaises(SafetyStop) as stop:
                self.install(tasks)
        self.assertIn("already exists", str(stop.exception))
        self.assertTrue(planted.is_file(), "a folder this did not create is never removed")
        self.assertEqual(tasks.registered, [])

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
        # The refused registration left nothing to delete, so schtasks reports the delete failed;
        # with no task registered, that is still a completed rollback, not an error.
        tasks = support.FakeTaskBackend(register_error=RecoveryError("schtasks refused the definition"))
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.deleted, 1)
        self.assertFalse(any(line.startswith("[ERROR]") for line in self.reporter.lines), self.reporter.lines)
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)

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

    def test_a_task_query_that_fails_stops_before_anything_is_staged(self) -> None:
        # A failed query is not an absent task. Read as absent, the installer would skip
        # capturing the previous task, and a failed registration could then only delete it.
        first = self.seed_previous_version()
        before_tree = support.tree_hash(first)
        tasks = support.FakeTaskBackend(
            status_error=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError) as stop:
            self.install(tasks)
        self.assertIn("could not be queried", str(stop.exception))
        self.assertEqual((tasks.registered, tasks.deleted, tasks.exported), ([], 0, 0))
        self.assertEqual(support.tree_hash(first), before_tree)
        staging = [path for path in install.versions_dir(self.root).iterdir() if payload.STAGING_SUFFIX in path.name]
        self.assertEqual(staging, [])

    def test_a_task_query_that_fails_on_a_first_install_creates_nothing(self) -> None:
        tasks = support.FakeTaskBackend(
            status_error=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertFalse(self.root.exists(), "the root is neither created nor repaired before the lookup")
        self.assertEqual(self.security.applied, [])

    def test_a_new_registration_that_cannot_be_checked_restores_the_previous_task(self) -> None:
        self.seed_previous_version()
        previous_xml = "<Task>the previous definition</Task>"
        tasks = support.FakeTaskBackend(
            status=self.tasks.automation_task_status(),
            xml=previous_xml,
            status_error_after_register=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.registered[-1], previous_xml, "the exact previous definition is put back")
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)
        broken = [path.name for path in install.versions_dir(self.root).iterdir()]
        self.assertTrue(any(name.endswith(payload.BROKEN_SUFFIX) for name in broken), broken)

    def test_a_new_registration_that_cannot_be_checked_is_removed_when_there_was_none(self) -> None:
        tasks = support.FakeTaskBackend(
            status_error_after_register=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertEqual(tasks.deleted, 1)
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)

    def test_a_rollback_delete_that_fails_is_reported_not_claimed(self) -> None:
        # schtasks reports a failed delete through its exit code, not an exception. Here the new
        # task was registered and checked wrong, so it is still there after the failed delete.
        tasks = support.FakeTaskBackend(status_override={"MultipleInstances": "Parallel"}, delete_returncode=1)
        with self.assertRaises(SafetyStop):
            self.install(tasks)
        self.assertEqual(tasks.deleted, 1)
        self.assertFalse(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)
        errors = [line for line in self.reporter.lines if line.startswith("[ERROR]")]
        self.assertEqual(len(errors), 1, self.reporter.lines)
        self.assertIn("could not be restored", errors[0])
        self.assertIn("Access is denied", errors[0])

    def test_a_rollback_that_cannot_tell_whether_the_task_is_gone_is_reported_not_claimed(self) -> None:
        tasks = support.FakeTaskBackend(register_error=RecoveryError("schtasks refused the definition"))
        # The registration is refused, and by the time the rollback asks, Task Scheduler cannot be read.
        original_delete = tasks.delete_task

        def delete_then_lose_the_scheduler():
            completed = original_delete()
            tasks.status_error = RecoveryError("Task Scheduler could not be queried: Access denied")
            return completed

        tasks.delete_task = delete_then_lose_the_scheduler
        with self.assertRaises(RecoveryError):
            self.install(tasks)
        self.assertFalse(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)
        errors = [line for line in self.reporter.lines if line.startswith("[ERROR]")]
        self.assertEqual(len(errors), 1, self.reporter.lines)
        self.assertIn("could not be queried", errors[0])

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

    def staged_handle(self, *, reparse: bool = False, final: str | None = None):
        """A stand-in for one staged file's handle, so the refusals can be reached.

        Neither a reparse point nor a path resolving outside the folder can be produced with
        an ordinary file: both refusals exist for states someone else creates. Injecting the
        handle is the only way to reach them deterministically.
        """
        from types import SimpleNamespace

        real = winapi.open_locked(self.quiet, open_reparse_point=True)
        self.addCleanup(real.close)
        return SimpleNamespace(
            is_reparse_point=lambda: reparse,
            final_path=lambda: final if final is not None else real.final_path(),
            close=lambda: None,
            stat=real.stat,
            read_chunks=real.read_chunks,
        )

    def test_a_staged_file_that_is_a_reparse_point_stops_the_install(self) -> None:
        handle = self.staged_handle(reparse=True)
        with mock.patch.object(install.winapi, "open_locked", return_value=handle):
            with self.assertRaises(SafetyStop) as stop:
                self.verify_staged()
        self.assertIn("is a reparse point", str(stop.exception))

    def test_a_staged_file_resolving_outside_the_folder_stops_the_install(self) -> None:
        handle = self.staged_handle(final=str(self.folder.parent / "elsewhere.exe"))
        with mock.patch.object(install.winapi, "open_locked", return_value=handle):
            with self.assertRaises(SafetyStop) as stop:
                self.verify_staged()
        self.assertIn("resolves outside the staged folder", str(stop.exception))

    def test_a_staged_file_with_unexpected_permissions_stops_the_install(self) -> None:
        from clauderestart.security import AclReport

        problem = "another account can write this file"
        self.security = support.FakeFileSecurity(
            child_verdict=AclReport(False, "S-1-5-32-544", [problem], [problem])
        )
        with self.assertRaises(SafetyStop) as stop:
            self.verify_staged()
        self.assertIn("unexpected permissions", str(stop.exception))
        self.assertIn(problem, str(stop.exception))

    def test_a_file_that_is_not_part_of_the_release_stops_the_install(self) -> None:
        (self.folder / "extra.dll").write_bytes(b"planted beside the staged payload")
        with self.assertRaises(SafetyStop) as stop:
            self.verify_staged()
        self.assertIn("not part of this release", str(stop.exception))

    def test_a_staged_twin_that_is_not_the_authenticated_one_stops_the_install(self) -> None:
        with self.assertRaises(SafetyStop) as stop:
            self.verify_staged(twin_sha="0" * 64)
        self.assertIn("not the one this build was made with", str(stop.exception))

    def test_a_committed_folder_that_is_not_protected_is_refused(self) -> None:
        # The rename puts the payload at a new name, so the folder's protection is proved again
        # there rather than assumed to have travelled with it.
        from clauderestart.security import AclReport

        problem = "another account can write here"
        self.security = support.FakeFileSecurity(
            verdicts=[AclReport(False, "S-1-5-32-544", [problem], [problem])]
        )
        with self.assertRaises(SafetyStop) as stop:
            self.verify_committed()
        self.assertIn(problem, str(stop.exception))
        self.assertIn("after the rename", str(stop.exception))

    def test_a_committed_folder_that_does_not_resolve_to_itself_is_refused(self) -> None:
        # The only check that the folder now standing at the final name is the folder that
        # was staged, and not a junction created between the rename and this check.
        from types import SimpleNamespace

        stub = SimpleNamespace(
            is_reparse_point=lambda: False,
            final_path=lambda: str(self.folder.parent / "somewhere-else"),
            close=lambda: None,
        )
        with mock.patch.object(install, "_open_owned_dir", return_value=stub):
            with self.assertRaises(SafetyStop) as stop:
                self.verify_committed()
        self.assertIn("did not resolve to itself", str(stop.exception))

    def test_a_committed_twin_that_does_not_resolve_to_itself_is_refused(self) -> None:
        # The last check that the file about to be hashed, permission checked and registered
        # with Task Scheduler is the real executable inside the committed folder.
        from types import SimpleNamespace

        real = winapi.open_locked(self.quiet)
        self.addCleanup(real.close)
        stub = SimpleNamespace(
            is_reparse_point=lambda: False,
            final_path=lambda: str(self.folder / "another.exe"),
            close=lambda: None,
            stat=real.stat,
            read_chunks=real.read_chunks,
        )
        with self.assertRaises(SafetyStop) as stop:
            install._verify_committed(self.folder, stub, self.manifest(), self.security, self.twin_sha)
        self.assertIn("did not resolve to itself", str(stop.exception))

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


@unittest.skipUnless(sys.platform == "win32", "the source task runs a Windows interpreter")
class SourceInstallTests(unittest.TestCase):
    """Registering the task to run a checkout follows the same lookup and rollback rules."""

    def setUp(self) -> None:
        self.reporter = reporting.Reporter()

    def test_a_lookup_that_fails_registers_nothing(self) -> None:
        tasks = support.FakeTaskBackend(
            status_error=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            install.install_from_source(self.reporter, package(), tasks=tasks)
        self.assertEqual((tasks.registered, tasks.deleted, tasks.exported), ([], 0, 0))

    def test_a_new_registration_that_cannot_be_checked_restores_the_previous_task(self) -> None:
        previous_xml = task_module.build_task_xml(
            Path(r"C:\Python314\pythonw.exe"),
            '"C:\\Users\\Example\\claude_restart.py" ' + task_module.TASK_ARGUMENTS,
            package().user_sid,
            Path(r"C:\Users\Example"),
        )
        tasks = support.FakeTaskBackend(
            status=support.FakeTaskBackend.status_from_xml(previous_xml),
            xml=previous_xml,
            status_error_after_register=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            install.install_from_source(self.reporter, package(), tasks=tasks)
        self.assertEqual(len(tasks.registered), 2)
        self.assertEqual(tasks.registered[-1], previous_xml, "the exact previous definition is put back")
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)

    def test_a_new_registration_that_cannot_be_checked_is_removed_when_there_was_none(self) -> None:
        tasks = support.FakeTaskBackend(
            status_error_after_register=RecoveryError("Task Scheduler could not be queried: Access denied"),
        )
        with self.assertRaises(RecoveryError):
            install.install_from_source(self.reporter, package(), tasks=tasks)
        self.assertEqual((len(tasks.registered), tasks.deleted), (1, 1))
        self.assertTrue(any(line.startswith("[RESTORED]") for line in self.reporter.lines), self.reporter.lines)
        self.assertFalse(any(line.startswith("[ERROR]") for line in self.reporter.lines), self.reporter.lines)


if __name__ == "__main__":
    unittest.main()
