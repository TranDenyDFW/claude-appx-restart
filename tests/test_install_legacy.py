"""The v1.0.2 flat install and removal behaviour.

Transitional: Step 7 replaces copy_to_install_dir and remove_install_dir with the
versioned transaction, and deletes this file. The replacements for each test are
listed in the plan's disposition table.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import install, payload, reporting  # noqa: E402


class InstallDirTests(unittest.TestCase):
    RELEASE = {
        "ClaudeRestart.exe": b"console",
        "ClaudeRestart-quiet.exe": b"quiet",
        "ClaudeRestart-launch.cmd": b"launch",
        "Install Automatic Recovery.cmd": b"install",
        "README.md": b"readme",
        "docs/windows-event-automation.md": b"docs",
        "unrelated.txt": b"not part of the release",
    }

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.source = root / "Downloads" / "ClaudeRestart-v1.0.2-win-x64"
        self.target = root / "Program Files" / "ClaudeRestart"
        for relative, content in self.RELEASE.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def frozen_at(self, folder: Path):
        return support.frozen_at(folder / payload.CONSOLE_EXE_NAME)

    def test_copy_installs_the_release_layout(self) -> None:
        reporter = reporting.Reporter()
        with self.frozen_at(self.source):
            location = install.copy_to_install_dir(reporter, self.target)
        self.assertEqual(location, self.target)
        for relative, content in self.RELEASE.items():
            installed = self.target / relative
            if relative == "unrelated.txt":
                self.assertFalse(installed.exists(), "files outside the release layout are not copied")
            else:
                self.assertEqual(installed.read_bytes(), content, relative)
        self.assertTrue(
            any(line.startswith("[COPIED] Installed 6 file(s)") for line in reporter.lines), reporter.lines
        )
        self.assertTrue(any("you can delete that folder" in line for line in reporter.lines))

    def test_copy_uses_canonical_names_for_a_renamed_download(self) -> None:
        (self.source / payload.CONSOLE_EXE_NAME).rename(self.source / "claude-restart-1.0.2.exe")
        (self.source / payload.QUIET_EXE_NAME).rename(self.source / "claude-restart-1.0.2-quiet.exe")
        with support.frozen_at(self.source / "claude-restart-1.0.2.exe"):
            install.copy_to_install_dir(reporting.Reporter(), self.target)
        self.assertEqual((self.target / payload.CONSOLE_EXE_NAME).read_bytes(), b"console")
        self.assertEqual((self.target / payload.QUIET_EXE_NAME).read_bytes(), b"quiet")

    def test_missing_quiet_twin_changes_nothing(self) -> None:
        (self.source / payload.QUIET_EXE_NAME).unlink()
        with self.frozen_at(self.source):
            with self.assertRaises(install.RecoveryError) as stop:
                install.copy_to_install_dir(reporting.Reporter(), self.target)
        self.assertIn("ClaudeRestart-quiet.exe was not found", str(stop.exception))
        self.assertFalse(self.target.exists(), "nothing is copied when a required file is missing")

    def test_copy_failure_is_reported_clearly(self) -> None:
        with self.frozen_at(self.source), mock.patch.object(
            install.shutil, "copyfile", side_effect=PermissionError("in use")
        ):
            with self.assertRaises(install.RecoveryError) as stop:
                install.copy_to_install_dir(reporting.Reporter(), self.target)
        self.assertIn("wait a minute and install again", str(stop.exception))

    def test_running_from_the_install_folder_copies_nothing(self) -> None:
        reporter = reporting.Reporter()
        with self.frozen_at(self.source):
            self.assertEqual(install.copy_to_install_dir(reporter, self.source), self.source)
        self.assertTrue(reporter.lines[0].startswith("[LOCATION] Already running from"))

    def test_remove_deletes_only_installed_files(self) -> None:
        with self.frozen_at(self.source):
            install.copy_to_install_dir(reporting.Reporter(), self.target)
        (self.target / payload.LOG_FILE_NAME).write_text("log", encoding="utf-8")
        (self.target / "keep-me.txt").write_text("user file", encoding="utf-8")
        reporter = reporting.Reporter()
        with self.frozen_at(self.source):
            install.remove_install_dir(reporter, self.target)
        self.assertEqual(sorted(p.name for p in self.target.rglob("*")), ["keep-me.txt"])
        self.assertTrue(any(line.startswith("[NOTE] Removed the installed files") for line in reporter.lines))

    def test_remove_deletes_the_folder_when_only_installed_files_remain(self) -> None:
        with self.frozen_at(self.source):
            install.copy_to_install_dir(reporting.Reporter(), self.target)
        reporter = reporting.Reporter()
        with self.frozen_at(self.source):
            install.remove_install_dir(reporter, self.target)
        self.assertFalse(self.target.exists())
        self.assertTrue(any(line.startswith("[REMOVED] Deleted") for line in reporter.lines))

    def test_remove_leaves_the_folder_it_is_running_from(self) -> None:
        reporter = reporting.Reporter()
        with self.frozen_at(self.source):
            install.remove_install_dir(reporter, self.source)
        self.assertTrue((self.source / payload.CONSOLE_EXE_NAME).exists())
        self.assertTrue(reporter.lines[0].startswith("[NOTE]"))


if __name__ == "__main__":
    unittest.main()
