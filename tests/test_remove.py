"""Removal deletes what this installer recorded, and nothing else.

The manifest written during installation is the only list consulted. A file that was
never installed, or one that changed since, is reported and kept; the folder goes only
when it is empty.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

import clauderestart  # noqa: E402
from clauderestart import install, payload, reporting, twin as twin_module, winapi  # noqa: E402
from clauderestart.errors import SafetyStop  # noqa: E402


QUIET_BYTES = b"the windowed executable"
CONSOLE_BYTES = b"the console executable"
VERSION = clauderestart.__version__


@unittest.skipUnless(sys.platform == "win32", "removal is a Windows operation")
class RemoveTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "Program Files" / payload.INSTALL_DIRNAME
        self.folder = install.versions_dir(self.root) / f"{VERSION}-abcdef12"
        self.folder.mkdir(parents=True)
        self.files = {
            payload.CONSOLE_EXE_NAME: CONSOLE_BYTES,
            payload.QUIET_EXE_NAME: QUIET_BYTES,
            "README.md": b"readme",
            "docs/windows-event-automation.md": b"docs",
        }
        recorded: dict[str, dict[str, object]] = {}
        for relative, content in self.files.items():
            path = self.folder / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            recorded[relative] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        install.InstallManifest(VERSION, "abcdef12", recorded, {}).write(self.folder)
        self.reporter = reporting.Reporter()
        self.security = support.FakeFileSecurity()

    def remove(self, **kwargs) -> None:
        install.remove_installation(self.reporter, self.root, backend=self.security, **kwargs)

    def test_a_clean_installation_is_removed_completely(self) -> None:
        self.remove()
        self.assertFalse(self.root.exists(), "nothing was left behind")
        self.assertTrue(any(line.startswith("[REMOVED]") for line in self.reporter.lines), self.reporter.lines)

    def test_a_file_the_installer_never_placed_survives(self) -> None:
        keep = self.folder / "notes.txt"
        keep.write_text("mine", encoding="utf-8")
        self.remove()
        self.assertTrue(keep.is_file())
        self.assertTrue(self.root.exists())
        self.assertTrue(any("notes.txt" in line for line in self.reporter.lines), self.reporter.lines)

    def test_an_unrecorded_file_with_a_recorded_name_survives(self) -> None:
        other = install.versions_dir(self.root) / f"{VERSION}-99999999"
        other.mkdir()
        impostor = other / payload.QUIET_EXE_NAME
        impostor.write_bytes(b"not ours")
        self.remove()
        self.assertTrue(impostor.is_file(), "a folder with no record of its own is left alone")

    def test_a_changed_file_is_kept_and_reported(self) -> None:
        (self.folder / payload.QUIET_EXE_NAME).write_bytes(b"changed after installation")
        self.remove()
        self.assertTrue((self.folder / payload.QUIET_EXE_NAME).is_file())
        self.assertTrue(any("changed since" in line for line in self.reporter.lines), self.reporter.lines)

    def test_a_changed_file_is_removed_only_when_forced(self) -> None:
        (self.folder / payload.QUIET_EXE_NAME).write_bytes(b"changed after installation")
        self.remove(force=True)
        self.assertFalse(self.root.exists())

    def test_an_entry_pointing_outside_the_folder_is_refused(self) -> None:
        victim = self.base / "victim.txt"
        victim.write_text("not ours", encoding="utf-8")
        manifest = install.InstallManifest.read(self.folder)
        manifest.files[r"..\..\victim.txt"] = {
            "sha256": hashlib.sha256(b"not ours").hexdigest(),
            "size": len(b"not ours"),
        }
        manifest.write(self.folder)
        self.remove()
        self.assertTrue(victim.is_file(), "a recorded path outside the folder is never followed")
        self.assertTrue(any("points outside" in line for line in self.reporter.lines), self.reporter.lines)

    def test_a_junction_in_the_tree_stops_the_removal(self) -> None:
        import _winapi  # noqa: PLC0415 - Windows-only helper

        victim = self.base / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("not ours", encoding="utf-8")
        _winapi.CreateJunction(str(victim), str(self.folder / "linked"))
        with self.assertRaises(SafetyStop) as stop:
            self.remove()
        self.assertIn("reparse point", str(stop.exception))
        self.assertTrue((victim / "precious.txt").is_file())
        self.assertTrue((self.folder / payload.QUIET_EXE_NAME).is_file(), "nothing was deleted")

    def test_the_folder_this_program_runs_from_is_left_in_place(self) -> None:
        running = self.folder / payload.CONSOLE_EXE_NAME
        with support.frozen_at(running):
            self.remove()
        self.assertTrue(running.is_file())
        self.assertTrue(any("running from it" in line for line in self.reporter.lines), self.reporter.lines)

    def test_the_legacy_flat_layout_is_removed_too(self) -> None:
        for relative in payload.LEGACY_ROOT_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"old flat install")
        self.remove()
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
