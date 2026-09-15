"""Authenticating the windowed twin against the record embedded in the console build.

The console executable is the trust root. A twin that does not match the embedded
record must stop the install, and the bytes that were hashed must be the bytes that
get used: the pathname is never reopened between checking and copying.
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

from clauderestart import payload, twin, winapi  # noqa: E402
from clauderestart.errors import RecoveryError, SafetyStop  # noqa: E402


QUIET_BYTES = b"windowed twin bytes"
OTHER_RELEASE_BYTES = b"windowed twin bytes from another release"


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
        self.twin_path.unlink()
        with self.assertRaises(SafetyStop) as stop:
            self.authenticate()
        message = str(stop.exception)
        self.assertIn(payload.QUIET_EXE_NAME, message)
        self.assertIn("ClaudeRestart-quiet.exe", message)

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


if __name__ == "__main__":
    unittest.main()
