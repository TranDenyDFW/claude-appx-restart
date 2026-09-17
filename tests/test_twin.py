"""Authenticating the windowed twin against the record embedded in the console build.

The console executable is the trust root. A twin that does not match the embedded
record must stop the install, and the bytes that were hashed must be the bytes that
get used: the pathname is never reopened between checking and copying.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import payload, twin, winapi  # noqa: E402
from clauderestart.errors import RecoveryError, SafetyStop  # noqa: E402


QUIET_BYTES = b"windowed twin bytes"
OTHER_RELEASE_BYTES = b"windowed twin bytes from another release"
# Same byte count as QUIET_BYTES, so the size check cannot refuse it and only the digest can.
SAME_LENGTH_TAMPERED = b"tampered twin bytes"
# Sentinel so a test can ask for no embedded record at all, which None cannot express here.
MATCHING_RECORD = object()


def record_for(data: bytes, *, version: str = "1.0.2", name: str = payload.QUIET_EXE_NAME) -> twin.EmbeddedTwin:
    return twin.EmbeddedTwin(
        name=name,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        version=version,
    )


class TwinAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.console = self.folder / payload.CONSOLE_EXE_NAME
        self.console.write_bytes(b"console bytes")
        self.twin_path = self.folder / payload.QUIET_EXE_NAME
        self.twin_path.write_bytes(QUIET_BYTES)
        self.record = record_for(QUIET_BYTES)

    def authenticate(self, *, embedded: twin.EmbeddedTwin | None = None, console: Path | None = None):
        console = console or self.console
        with support.frozen_at(console):
            return twin.authenticate_twin(console, embedded=embedded if embedded is not None else self.record)

    def test_matching_twin_is_authenticated_and_held_open(self) -> None:
        authenticated = self.authenticate()
        self.addCleanup(authenticated.close)
        self.assertEqual(authenticated.path, self.twin_path)
        self.assertEqual(authenticated.sha256, self.record.sha256)
        self.assertEqual(authenticated.size, len(QUIET_BYTES))
        self.assertEqual(b"".join(authenticated.locked.read_chunks()), QUIET_BYTES)

    def test_arbitrary_bytes_are_refused(self) -> None:
        self.twin_path.write_bytes(b"arbitrary bytes planted beside the console build")
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate()
        message = str(stop.exception)
        self.assertIn(self.record.sha256, message)
        self.assertIn(payload.QUIET_EXE_NAME, message)

    def test_a_twin_from_another_release_is_refused(self) -> None:
        self.twin_path.write_bytes(OTHER_RELEASE_BYTES)
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate()
        self.assertIn(hashlib.sha256(OTHER_RELEASE_BYTES).hexdigest(), str(stop.exception))

    def test_a_same_length_tampered_twin_is_refused_by_the_digest_alone(self) -> None:
        # Without this fixture the digest comparison is dead weight: every other tampering case
        # differs in length, so the size check decides and removing the digest check stays green.
        self.assertEqual(len(SAME_LENGTH_TAMPERED), len(QUIET_BYTES))
        self.assertNotEqual(SAME_LENGTH_TAMPERED, QUIET_BYTES)
        self.twin_path.write_bytes(SAME_LENGTH_TAMPERED)
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate()
        message = str(stop.exception)
        self.assertIn(hashlib.sha256(SAME_LENGTH_TAMPERED).hexdigest(), message)
        self.assertIn(self.record.sha256, message)

    def test_size_mismatch_with_a_matching_digest_is_refused(self) -> None:
        wrong_size = twin.EmbeddedTwin(
            name=self.record.name, sha256=self.record.sha256, size=self.record.size + 1, version="1.0.2"
        )
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate(embedded=wrong_size)
        self.assertIn("bytes", str(stop.exception))

    def test_a_build_without_an_embedded_record_refuses(self) -> None:
        with support.frozen_at(self.console), mock.patch.object(twin, "load_embedded_twin", return_value=None):
            with self.assertRaises(SafetyStop) as stop:
                twin.authenticate_twin(self.console)
        self.assertIn("no record", str(stop.exception))

    def test_a_missing_twin_names_both_candidates(self) -> None:
        # Beside a console named ClaudeRestart.exe the canonical and stem derived candidate names
        # are the same string, so a two candidate assertion there proves nothing. Rename it.
        renamed_console = self.folder / "claude-restart-1.0.2.exe"
        self.console.rename(renamed_console)
        self.twin_path.unlink()
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate(console=renamed_console)
        message = str(stop.exception)
        self.assertNotEqual(payload.QUIET_EXE_NAME, "claude-restart-1.0.2-quiet.exe")
        self.assertIn(payload.QUIET_EXE_NAME, message)
        self.assertIn("claude-restart-1.0.2-quiet.exe", message)

    def test_a_renamed_pair_authenticates_the_stem_named_twin(self) -> None:
        renamed_console = self.folder / "claude-restart-1.0.2.exe"
        self.console.rename(renamed_console)
        renamed_twin = self.folder / "claude-restart-1.0.2-quiet.exe"
        self.twin_path.rename(renamed_twin)
        authenticated = self.authenticate(console=renamed_console)
        self.addCleanup(authenticated.close)
        self.assertEqual(authenticated.path, renamed_twin)

    def test_no_fall_through_when_the_canonical_twin_fails(self) -> None:
        # Both names live in the same folder, so a second name is no more trustworthy.
        renamed_console = self.folder / "claude-restart-1.0.2.exe"
        self.console.rename(renamed_console)
        (self.folder / "claude-restart-1.0.2-quiet.exe").write_bytes(QUIET_BYTES)
        self.twin_path.write_bytes(b"tampered")
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate(console=renamed_console)
        message = str(stop.exception)
        self.assertIn(payload.QUIET_EXE_NAME, message)
        self.assertIn("claude-restart-1.0.2-quiet.exe", message)

    def test_the_checksums_file_beside_the_build_is_never_consulted(self) -> None:
        wrong = self.folder / payload.CHECKSUMS_NAME
        wrong.write_text("0" * 64 + "  ClaudeRestart-quiet.exe\n", encoding="utf-8")
        authenticated = self.authenticate()
        self.assertEqual(authenticated.sha256, self.record.sha256)
        # Release the lock before tampering: while it is held, nobody can rewrite the file.
        authenticated.close()

        correct = hashlib.sha256(b"tampered").hexdigest()
        wrong.write_text(f"{correct}  ClaudeRestart-quiet.exe\n", encoding="utf-8")
        self.twin_path.write_bytes(b"tampered")
        with self.assertRaises(SafetyStop):
            self.authenticate()

    def test_a_source_run_never_authenticates(self) -> None:
        with self.assertRaises(RecoveryError) as stop:
            twin.authenticate_twin(self.console, embedded=self.record)
        self.assertIn("source run", str(stop.exception))


@unittest.skipUnless(sys.platform == "win32", "file sharing modes are Windows-only")
class LockedFileTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.target = self.folder / payload.QUIET_EXE_NAME
        self.target.write_bytes(QUIET_BYTES)

    def test_an_open_lock_denies_write_rename_and_delete(self) -> None:
        locked = winapi.open_locked(self.target)
        try:
            with self.assertRaises(PermissionError):
                open(self.target, "wb").close()
            with self.assertRaises(PermissionError):
                os.remove(self.target)
            with self.assertRaises(PermissionError):
                os.rename(self.target, self.folder / "moved.exe")
            with self.assertRaises(PermissionError):
                os.replace(self.folder / "other.exe" if False else self.target, self.folder / "swapped.exe")
        finally:
            locked.close()
        # After closing, the same operations succeed.
        os.rename(self.target, self.folder / "moved.exe")
        self.assertTrue((self.folder / "moved.exe").is_file())

    def test_authentication_refuses_when_another_program_holds_the_file(self) -> None:
        console = self.folder / payload.CONSOLE_EXE_NAME
        console.write_bytes(b"console bytes")
        holder = open(self.target, "r+b")
        self.addCleanup(holder.close)
        with support.frozen_at(console):
            with self.assertRaises(SafetyStop) as stop:
                twin.authenticate_twin(console, embedded=record_for(QUIET_BYTES))
        self.assertIn("could not be opened", str(stop.exception))

    def test_final_path_is_the_canonical_path_and_close_is_idempotent(self) -> None:
        locked = winapi.open_locked(self.target)
        try:
            self.assertEqual(locked.final_path(), winapi.canonical(self.target))
            self.assertFalse(locked.is_reparse_point())
            self.assertEqual(locked.size(), len(QUIET_BYTES))
        finally:
            locked.close()
            locked.close()

    def test_a_directory_handle_needs_the_directory_flag(self) -> None:
        locked = winapi.open_locked(self.folder, directory=True, share=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE)
        try:
            self.assertEqual(locked.final_path(), winapi.canonical(self.folder))
            self.assertFalse(locked.is_reparse_point())
        finally:
            locked.close()


@unittest.skipUnless(sys.platform == "win32", "the entry point locks its own executable")
class InstallEntryPointTests(unittest.TestCase):
    """Drive cli.main all the way through a frozen install.

    No test reached this path before. The only installer test took the unknown identity
    branch and returned before the twin was ever touched, so a missing import on the line
    that authenticates the twin shipped with a green suite: the run exited 3 with an
    internal error instead of the documented safety stop, having verified nothing and
    installed nothing.
    """

    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.console = self.folder / payload.CONSOLE_EXE_NAME
        self.console.write_bytes(b"console bytes")
        # Registered after the directory cleanup so it runs first: the lock must be released
        # before the temporary folder can be removed.
        self.addCleanup(self.release_console_lock)

    def release_console_lock(self) -> None:
        lock = getattr(twin, "_console_lock", None)
        if lock is not None:
            lock.close()
        twin._console_lock = None

    def confirmed_package(self):
        from clauderestart import package as package_module

        return package_module.PackageInfo(
            name="Claude",
            version="1.52386.6.0",
            package_full_name="Claude_1.52386.6.0_x64__pzs8sxrjxfjjc",
            package_family_name=package_module.EXPECTED_PACKAGE_FAMILY,
            install_location=str(self.folder),
            application_id="Claude",
            user_sid="S-1-5-21-0-0-0-1001",
        )

    def run_main(self, *argv: str, embedded: object = MATCHING_RECORD):
        """Run the entry point and return its exit code, the task backend, and its output.

        The embedded record is supplied explicitly. A source checkout carries the placeholder,
        so without this every case would refuse for a missing record before it ever looked for
        the twin, and each test would pass for the wrong reason.
        """
        from clauderestart import cli

        record = record_for(QUIET_BYTES) if embedded is MATCHING_RECORD else embedded
        stream = io.StringIO()
        with support.frozen_at(self.console), mock.patch.object(
            sys, "argv", [str(self.console), *argv]
        ), mock.patch.object(winapi, "is_admin", return_value=True), mock.patch.object(
            twin, "load_embedded_twin", return_value=record
        ), mock.patch.object(
            cli, "get_claude_package", return_value=self.confirmed_package()
        ), mock.patch.object(cli.task, "register_task_xml") as register, contextlib.redirect_stdout(stream):
            return cli.main(), register, stream.getvalue()

    def test_a_missing_twin_exits_with_the_safety_stop_code(self) -> None:
        self.assertFalse((self.folder / payload.QUIET_EXE_NAME).exists())
        exit_code, register, output = self.run_main("--install-automation", "--no-elevate")
        self.assertEqual(exit_code, 2)
        self.assertIn("was not found beside", output)
        register.assert_not_called()

    def test_a_tampered_twin_exits_with_the_safety_stop_code(self) -> None:
        (self.folder / payload.QUIET_EXE_NAME).write_bytes(SAME_LENGTH_TAMPERED)
        exit_code, register, output = self.run_main("--install-automation", "--no-elevate")
        self.assertEqual(exit_code, 2)
        self.assertIn("is not the windowed twin this build was made with", output)
        register.assert_not_called()

    def test_a_build_without_a_record_exits_with_the_safety_stop_code(self) -> None:
        (self.folder / payload.QUIET_EXE_NAME).write_bytes(QUIET_BYTES)
        exit_code, register, output = self.run_main("--install-automation", "--no-elevate", embedded=None)
        self.assertEqual(exit_code, 2)
        self.assertIn("carries no record of its windowed twin", output)
        register.assert_not_called()

    def test_the_install_path_never_reports_an_internal_error(self) -> None:
        # Exit 3 means an exception reached the last resort handler. That is exactly what a
        # name used but never imported produced on this path, and no other test would see it.
        exit_code, _, output = self.run_main("--install-automation", "--no-elevate")
        self.assertNotEqual(exit_code, 3)
        self.assertNotIn("INTERNAL ERROR", output)


if __name__ == "__main__":
    unittest.main()
