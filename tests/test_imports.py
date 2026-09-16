"""The package import rules that keep the split honest.

Rule 1: the leaf modules (payload, errors, winapi, shell) import nothing from the
package except errors.
Rule 2: consumers write `from . import winapi` and read winapi.is_frozen() and the
DLL handles at call time, so tests have one patch point.
Rule 3: no package module imports cli, so there is no cycle back to the entry point.
"""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402


PACKAGE = support.ROOT / "clauderestart"
LEAVES = {"payload", "errors", "winapi", "shell"}
LEAF_ALLOWED = {"errors"}
CALL_TIME_NAMES = {"is_frozen", "IS_FROZEN", "kernel32", "ntdll", "advapi32", "shell32", "user32", "ole32"}


def violations(module_name: str, source: str) -> list[str]:
    """Return one message per import rule the module source breaks."""
    problems: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            names = {alias.name for alias in node.names}
            target = node.module or ""
            if node.level >= 1:
                imported = {target} if target else names
                if module_name in LEAVES and imported - LEAF_ALLOWED:
                    problems.append(f"{module_name}: leaf imports {sorted(imported - LEAF_ALLOWED)}")
                if "cli" in imported and module_name != "cli":
                    problems.append(f"{module_name}: imports cli")
                if target == "winapi" and names & CALL_TIME_NAMES:
                    problems.append(f"{module_name}: binds {sorted(names & CALL_TIME_NAMES)} at import time")
            elif target.startswith("clauderestart"):
                problems.append(f"{module_name}: absolute package import {target}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("clauderestart"):
                    problems.append(f"{module_name}: absolute package import {alias.name}")
    return problems


class ImportRuleTests(unittest.TestCase):
    def test_every_module_follows_the_import_rules(self) -> None:
        found: list[str] = []
        for path in sorted(PACKAGE.glob("*.py")):
            found.extend(violations(path.stem, path.read_text(encoding="utf-8")))
        self.assertEqual(found, [], "\n".join(found))

    def test_the_scan_reports_known_bad_sources(self) -> None:
        # The check must be able to fail: feed it one violation of each rule.
        self.assertTrue(violations("recovery", "from .winapi import kernel32\n"))
        self.assertTrue(violations("payload", "from . import winapi\n"))
        self.assertTrue(violations("task", "from .cli import main\n"))
        self.assertTrue(violations("task", "import clauderestart.cli\n"))
        self.assertEqual(violations("recovery", "from . import winapi\nfrom .errors import SafetyStop\n"), [])

    def test_the_package_imports_cleanly_in_a_fresh_interpreter(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-c", "import clauderestart.cli"],
            cwd=str(support.ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
