"""The acceptance checker itself, which decides whether the coverage map can be trusted.

It had no test at all, and a map validated only by hand is a claim rather than a check. Each
case here is a way a row can read as evidence while proving nothing: a test that was renamed
away, a file that no longer exists, a row shaped so the parser skips it in silence.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_checker():
    """Load the tool by path; tools/ is not a package."""
    spec = importlib.util.spec_from_file_location("check_acceptance", ROOT / "tools" / "check_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_acceptance"] = module
    spec.loader.exec_module(module)
    return module


class AcceptanceCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.checker = load_checker()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def table(self, *rows: str) -> Path:
        path = self.folder / "acceptance.md"
        body = "| Review item | Evidence |\n|---|---|\n" + "".join(f"{row}\n" for row in rows)
        path.write_text(body, encoding="utf-8")
        return path

    def test_the_real_table_passes(self) -> None:
        self.assertEqual(self.checker.check(ROOT / "tests" / "ACCEPTANCE.md"), [])

    def test_a_row_naming_a_test_that_does_not_exist_fails(self) -> None:
        problems = self.checker.check(self.table("| a claim | tests/test_twin.py::test_this_does_not_exist |"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("test_this_does_not_exist", problems[0])

    def test_a_row_naming_a_test_file_that_does_not_exist_fails(self) -> None:
        problems = self.checker.check(self.table("| a claim | tests/test_not_here.py::test_x |"))
        self.assertTrue(problems)
        self.assertTrue(any("test_not_here.py" in problem for problem in problems), problems)

    def test_a_row_naming_a_tool_that_does_not_exist_fails(self) -> None:
        # A rename that leaves a dangling reference behind still reads as evidence.
        problems = self.checker.check(self.table("| a claim | manual: enforced by tools/not_a_tool.py |"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("tools/not_a_tool.py", problems[0])

    def test_a_row_naming_a_workflow_file_that_does_not_exist_fails(self) -> None:
        # A rename under .github went unnoticed because only tests, tools and docs were checked.
        problems = self.checker.check(
            self.table("| a claim | manual: enforced by .github/workflows/not-a-workflow.yml |")
        )
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(".github/workflows/not-a-workflow.yml", problems[0])

    def test_root_files_that_exist_are_accepted(self) -> None:
        # The widened pattern must not start rejecting the root files rows legitimately name.
        problems = self.checker.check(self.table("| a claim | manual: see not_a_module.py and build.py |"))
        self.assertEqual(problems, [], "a root file that exists is accepted")
        problems = self.checker.check(self.table("| a claim | manual: see ClaudeRestart.spec |"))
        self.assertEqual(problems, [], "the spec exists")

    def test_a_row_that_is_not_two_columns_is_reported(self) -> None:
        problems = self.checker.check(self.table("| a claim | evidence | an extra column |"))
        self.assertTrue(any("not two columns" in problem for problem in problems), problems)

    def test_a_row_with_neither_a_test_nor_a_manual_step_fails(self) -> None:
        problems = self.checker.check(self.table("| a claim | it works |"))
        self.assertTrue(any("no test" in problem for problem in problems), problems)

    def test_a_table_with_no_rows_fails(self) -> None:
        path = self.folder / "empty.md"
        path.write_text("# nothing here\n", encoding="utf-8")
        self.assertTrue(self.checker.check(path))


if __name__ == "__main__":
    unittest.main()
