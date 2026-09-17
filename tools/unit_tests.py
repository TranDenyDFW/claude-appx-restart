#!/usr/bin/env python3
"""Run the unit tests, and with --forbid-skips treat a skipped test as a failure.

A plain `python -m unittest discover` exits 0 whether a test runs or skips. Several tests
here are gated on elevation, so a runner that counts a skip as success cannot tell a proved
control from an absent one: a green job would look identical either way. Continuous
integration runs elevated, so it forbids skips and names any that occur.

    py -3 tools/unit_tests.py
    py -3 tools/unit_tests.py --forbid-skips
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the unit tests.")
    parser.add_argument(
        "--forbid-skips",
        action="store_true",
        help="exit non-zero when any test is skipped, naming each one",
    )
    parser.add_argument("--verbosity", type=int, default=2)
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT / "tests"))
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 1

    result = unittest.TextTestRunner(verbosity=args.verbosity).run(suite)

    if result.skipped:
        print(f"\n{len(result.skipped)} test(s) skipped:")
        for test, reason in result.skipped:
            print(f"  {test.id()}: {reason}")

    if args.forbid_skips and result.skipped:
        print(
            "\nThis run does not allow skipped tests. A control that skips is not a control, "
            "and the job would be green either way.",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
