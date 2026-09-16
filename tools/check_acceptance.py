#!/usr/bin/env python3
"""Check that every acceptance row names a test that exists.

tests/ACCEPTANCE.md maps each review item to the test that covers it. A row naming a
test that was renamed or deleted is worse than no row at all, because it reads as
coverage. This walks the table and confirms every referenced test is really there.

    py -3 tools/check_acceptance.py
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TABLE_ROW = re.compile(r"^\|(?P<item>[^|]+)\|(?P<evidence>[^|]+)\|\s*$")
TEST_REFERENCE = re.compile(r"(?P<file>tests/[A-Za-z0-9_]+\.py)(?:::(?P<test>[A-Za-z0-9_]+))?")
# Any repository file a row names, not just a test file. A row that points at a tool which
# was renamed or deleted reads as evidence and is worth nothing.
FILE_REFERENCE = re.compile(
    r"(?P<file>(?:\.github/|tests/|tools/|docs/)[A-Za-z0-9_./-]+\.(?:py|md|txt|yml)"
    r"|(?<![\w/])(?:build\.py|claude_restart\.py|ClaudeRestart\.spec|README\.md))"
)


def known_tests(path: Path) -> set[str]:
    """Every test method name defined in one test file."""
    names: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            names.add(node.name)
    return names


def check(acceptance: Path) -> list[str]:
    problems: list[str] = []
    rows = 0
    references = 0
    for number, line in enumerate(acceptance.read_text(encoding="utf-8").splitlines(), start=1):
        match = TABLE_ROW.match(line)
        if not match:
            # A line that looks like a table row but is not two columns was silently ignored,
            # so a malformed row could carry a claim nothing ever checked.
            if line.lstrip().startswith("|"):
                problems.append(f"line {number} looks like a table row but is not two columns: {line.strip()}")
            continue
        evidence_cell = match.group("evidence").strip()
        # Skip a table's own header and its separator line, which carry no evidence.
        if set(evidence_cell) <= {"-", ":", " "} or evidence_cell.lower() == "evidence":
            continue
        rows += 1
        evidence = match.group("evidence")
        found = list(TEST_REFERENCE.finditer(evidence))
        if not found and "manual" not in evidence.lower():
            problems.append(f"row names no test and no manual step: {match.group('item').strip()}")
        for reference in FILE_REFERENCE.finditer(evidence):
            named = reference.group("file")
            if not (ROOT / named).is_file():
                problems.append(f"line {number} names {named}, which does not exist")
        for reference in found:
            references += 1
            path = ROOT / reference.group("file")
            if not path.is_file():
                problems.append(f"{reference.group('file')} does not exist")
                continue
            test = reference.group("test")
            if test and test not in known_tests(path):
                problems.append(f"{reference.group('file')} has no test named {test}")
    if not rows:
        problems.append("the acceptance table has no rows")
    print(f"{rows} row(s), {references} test reference(s) checked")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the acceptance table against the tests.")
    parser.add_argument("--file", default=str(ROOT / "tests" / "ACCEPTANCE.md"))
    args = parser.parse_args()
    problems = check(Path(args.file))
    if problems:
        print("\nThe acceptance table does not match the tests:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("Every referenced test exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
