"""The install root must be administrator-only before any file or task is touched.

These tests drive verify_root with a scripted security backend and a real temporary
tree, so the reparse-point and hard-link checks run against real Windows behaviour while
the permission verdicts are supplied by the fake. Every refusal must leave the tree and
the scheduled task exactly as they were.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import install, payload, reporting, security, winapi  # noqa: E402
from clauderestart.errors import SafetyStop  # noqa: E402
from clauderestart.security import AclReport  # noqa: E402


def blocking_report(problem: str) -> AclReport:
    return AclReport(False, "S-1-5-21-1-2-3-1001", [problem], [problem])


def repairable_report(problem: str) -> AclReport:
    return AclReport(False, security.SID_ADMINISTRATORS, [problem], [])


def ok_report() -> AclReport:
    return AclReport(True, security.SID_ADMINISTRATORS, [], [])


@unittest.skipUnless(sys.platform == "win32", "the install root is a Windows path")
class VerifyRootTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.program_files = self.base / "Program Files"
        self.program_files.mkdir()
        self.root = self.program_files / payload.INSTALL_DIRNAME
        self.reporter = reporting.Reporter()

    def junction(self, link: Path, target: Path) -> None:
        import _winapi  # noqa: PLC0415 - Windows-only helper

        target.mkdir(parents=True, exist_ok=True)
        _winapi.CreateJunction(str(target), str(link))

    def test_a_fresh_root_is_created_protected_and_verified(self) -> None:
        backend = support.FakeFileSecurity()
        returned = install.verify_root(self.reporter, backend, self.root)
        self.assertEqual(returned, self.root)
        self.assertTrue(self.root.is_dir())
        self.assertTrue(install.versions_dir(self.root).is_dir())
        self.assertEqual(backend.applied, [str(self.root), str(install.versions_dir(self.root))])
        self.assertTrue(any(line.startswith("[PROTECTED]") for line in self.reporter.lines), self.reporter.lines)

    def test_a_failed_permission_apply_leaves_no_folder_behind(self) -> None:
        backend = support.FakeFileSecurity(apply_error=OSError("access is denied"))
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("administrator-only", str(stop.exception))
        self.assertFalse(self.root.exists(), "a root that could not be protected must not survive")

    def test_a_fresh_root_that_does_not_verify_is_removed(self) -> None:
        backend = support.FakeFileSecurity(verdicts=[repairable_report("the permission list is wrong")])
        with self.assertRaises(SafetyStop):
            install.verify_root(self.reporter, backend, self.root)
        self.assertFalse(self.root.exists())

    def test_an_existing_root_with_a_blocking_verdict_is_refused(self) -> None:
        self.root.mkdir()
        backend = support.FakeFileSecurity(
            verdicts=[ok_report(), blocking_report("ACE 3 grants write data to S-1-5-21-1-2-3-1001")]
        )
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        message = str(stop.exception)
        self.assertIn("write data", message)
        self.assertIn("Delete that folder by hand", message)
        self.assertEqual(backend.applied, [], "a folder others can change is never repaired in place")
        self.assertFalse(install.versions_dir(self.root).exists())

    def test_an_existing_root_with_a_repairable_verdict_is_corrected(self) -> None:
        self.root.mkdir()
        backend = support.FakeFileSecurity(
            verdicts=[
                ok_report(),  # scan_tree asks about the root first
                repairable_report("the permission list still inherits from Program Files"),
                ok_report(),  # after the repair
            ]
        )
        install.verify_root(self.reporter, backend, self.root)
        self.assertEqual(backend.applied[0], str(self.root))
        self.assertTrue(any(line.startswith("[REPAIR]") for line in self.reporter.lines), self.reporter.lines)
        self.assertTrue(install.versions_dir(self.root).is_dir())

    def test_a_repair_that_cannot_proceed_is_a_safety_stop(self) -> None:
        # Enabling the privileges a repair needs can fail. The create path already reports that
        # as a safety stop; this path let a plain error through, so the same condition produced
        # "error" and exit 1 instead of "nothing was changed" and exit 2.
        from clauderestart.errors import RecoveryError

        self.root.mkdir()
        backend = support.FakeFileSecurity(
            verdicts=[
                ok_report(),
                repairable_report("the permission list still inherits from Program Files"),
            ],
            apply_error=RecoveryError("a required privilege is not held by the client"),
        )
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("could not be corrected", str(stop.exception))
        self.assertIn("a required privilege", str(stop.exception))

    def test_a_repair_that_does_not_hold_is_refused(self) -> None:
        self.root.mkdir()
        backend = support.FakeFileSecurity(
            verdicts=[
                ok_report(),
                repairable_report("the permission list still inherits from Program Files"),
                repairable_report("the permission list still inherits from Program Files"),
            ]
        )
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("could not be corrected", str(stop.exception))

    def test_a_junction_inside_the_root_is_refused(self) -> None:
        self.root.mkdir()
        victim = self.base / "victim"
        self.junction(self.root / payload.VERSIONS_DIRNAME, victim)
        (victim / "precious.txt").write_text("not ours", encoding="utf-8")
        backend = support.FakeFileSecurity()
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("reparse point", str(stop.exception))
        self.assertEqual(backend.applied, [])
        self.assertTrue((victim / "precious.txt").is_file(), "the junction target must be untouched")

    def test_a_junction_at_program_files_is_refused(self) -> None:
        real = self.base / "real Program Files"
        link = self.base / "linked Program Files"
        self.junction(link, real)
        backend = support.FakeFileSecurity()
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, link / payload.INSTALL_DIRNAME)
        self.assertIn("Program Files", str(stop.exception))
        self.assertEqual(backend.applied, [])

    @unittest.skipUnless(
        sys.platform == "win32" and winapi.is_admin(), "creating a file symbolic link needs elevation"
    )
    def test_a_symbolic_link_on_a_file_in_the_root_is_refused(self) -> None:
        """A link on a file entry, which only the per entry check can see.

        The junction fixture points at a directory, and the folder check refuses that with
        its own wording, so the per entry reparse check was never the thing that refused.
        """
        self.root.mkdir()
        outside = self.base / "outside.txt"
        outside.write_text("a file somewhere else entirely", encoding="utf-8")
        os.symlink(outside, self.root / payload.CONSOLE_EXE_NAME)
        backend = support.FakeFileSecurity()
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("reparse point", str(stop.exception))
        self.assertEqual(backend.applied, [], "nothing is repaired when a link is present")

    def test_a_hard_linked_file_in_the_root_is_refused(self) -> None:
        self.root.mkdir()
        original = self.root / "ClaudeRestart.exe"
        original.write_bytes(b"installed")
        try:
            os.link(original, self.root / "second-name.exe")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard links are not available here: {exc}")
        backend = support.FakeFileSecurity()
        with self.assertRaises(SafetyStop) as stop:
            install.verify_root(self.reporter, backend, self.root)
        self.assertIn("more than one name", str(stop.exception))
        self.assertEqual(backend.applied, [])


@unittest.skipUnless(sys.platform == "win32", "known folders are Windows-only")
class ProgramFilesTests(unittest.TestCase):
    def test_program_files_comes_from_the_shell_not_the_environment(self) -> None:
        winapi.configure()
        real = winapi.program_files_dir()
        self.assertTrue(real.is_absolute() and real.is_dir())
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"ProgramFiles": tmp, "ProgramW6432": tmp}):
                self.assertEqual(winapi.program_files_dir(), real)
        self.assertEqual(install.install_dir(), real / payload.INSTALL_DIRNAME)
        self.assertEqual(install.versions_dir(), real / payload.INSTALL_DIRNAME / payload.VERSIONS_DIRNAME)


if __name__ == "__main__":
    unittest.main()
