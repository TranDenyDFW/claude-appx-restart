"""Where the run log is written, and which file a launcher must run."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import payload, reporting  # noqa: E402


class ReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_save_writes_beside_the_tool(self) -> None:
        reporter = reporting.Reporter()
        reporter.lines.append("[TEST] hello")
        target = reporter.save(base=self.root)
        self.assertEqual(target, self.root / payload.LOG_FILE_NAME)
        self.assertIn("[TEST] hello", target.read_text(encoding="utf-8"))

    def test_save_falls_back_when_the_tool_folder_is_unwritable(self) -> None:
        blocker = self.root / "not-a-directory"
        blocker.write_text("x", encoding="utf-8")
        fallback = self.root / "fallback"
        reporter = reporting.Reporter()
        reporter.lines.append("[TEST] fallback")
        target = reporter.save(base=blocker, fallback=fallback)
        self.assertEqual(target, fallback / payload.LOG_FILE_NAME)
        self.assertTrue(target.is_file())

    def test_save_skips_an_empty_run(self) -> None:
        self.assertIsNone(reporting.Reporter().save(base=self.root))
        self.assertFalse((self.root / payload.LOG_FILE_NAME).exists())

    def test_reporter_persists_by_default(self) -> None:
        self.assertTrue(reporting.Reporter().persist)


class AppEntryTests(unittest.TestCase):
    def test_from_source_the_entry_is_the_entry_script(self) -> None:
        entry = reporting.app_entry()
        self.assertEqual(entry.name, "claude_restart.py")
        self.assertTrue(entry.is_file(), entry)
        self.assertEqual(reporting.app_location(), support.ROOT)

    def test_frozen_entry_is_the_executable_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp).resolve() / payload.CONSOLE_EXE_NAME
            exe.write_bytes(b"")
            with support.frozen_at(exe):
                self.assertEqual(reporting.app_entry(), exe)
                self.assertEqual(reporting.app_location(), exe.parent)


if __name__ == "__main__":
    unittest.main()
