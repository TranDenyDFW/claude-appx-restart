#!/usr/bin/env python3
"""Prove the security tests can fail, by removing each behaviour and requiring a red test.

A test suite that stays green when the behaviour it claims to protect is deleted proves
nothing. Every entry below is a behaviour this project's security claims rest on, and every
one of them once survived deletion with the whole suite green. Each is applied to a throwaway
copy of the tree; the named test file must turn red.

A mutation whose text no longer matches is reported and fails the run. That is deliberate:
after a refactor the guard must be updated rather than silently passing on a mutation it can
no longer apply.

    py -3 tools/mutation_guard.py
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(".git", "tmp", "dist", "build", ".venv-build", "__pycache__", ".md")

# (label, file, exact text to remove or weaken, replacement, the test file that must turn red)
MUTATIONS = [
    (
        "the twin digest comparison",
        "clauderestart/twin.py",
        "if observed != record.sha256 or size != record.size:",
        "if size != record.size:",
        "tests.test_twin",
    ),
    (
        "the membership growth guard during validation",
        "clauderestart/recovery.py",
        """    added = recheck - snapshot
    if added:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: it gained member(s) {sorted(added)} while they were being "
            "checked, so they were never verified."
        )""",
        "    added = recheck - snapshot",
        "tests.test_recovery_race",
    ),
    (
        "the Path import the frozen install path needs",
        "clauderestart/cli.py",
        "import os\nfrom pathlib import Path\nimport subprocess",
        "import os\nimport subprocess",
        "tests.test_twin",
    ),
    (
        "the check that the registered task runs the installed executable",
        "clauderestart/task.py",
        """    registered = task_command_path(status.get("Execute"))
    if winapi.canonical(registered) != winapi.canonical(executable):
        problems.append(f"the task runs {registered}, expected {executable}")
    return problems""",
        "    return problems",
        "tests.test_task_xml",
    ),
    (
        "the build stage guard digest comparison",
        "build.py",
        "    if digest != record.sha256 or size != record.size:",
        "    if size != record.size:",
        "tests.test_build",
    ),
    (
        "the build stage guard refusing an absent twin",
        "build.py",
        """    if not built.is_file():
        sys.exit(
            f"The console stage has no windowed twin at {built} to check its record against, so the "
            "record cannot be trusted. Run: py -3 build.py"
        )""",
        "    if not built.is_file():\n        return record",
        "tests.test_build",
    ),
]


def run(subject: Path, module: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "unittest", module],
        cwd=str(subject),
        capture_output=True,
        text=True,
    )


def main() -> int:
    survivors: list[str] = []
    for label, relative, old, new, module in MUTATIONS:
        with tempfile.TemporaryDirectory() as work:
            subject = Path(work) / "subject"
            shutil.copytree(ROOT, subject, ignore=IGNORE)

            target = subject / relative
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"STALE    {label}: the text matched {text.count(old)} time(s), expected 1")
                survivors.append(label)
                continue

            baseline = run(subject, module)
            if baseline.returncode != 0:
                print(f"BROKEN   {label}: {module} already fails unmutated, so the result means nothing")
                survivors.append(label)
                continue

            target.write_text(text.replace(old, new), encoding="utf-8")
            mutated = run(subject, module)
            if mutated.returncode == 0:
                print(f"SURVIVED {label}: {module} stayed green with the behaviour removed")
                survivors.append(label)
            else:
                summary = [line for line in mutated.stderr.splitlines() if line.strip()][-1]
                print(f"CAUGHT   {label}: {module} turned red ({summary})")

    caught = len(MUTATIONS) - len(survivors)
    print(f"\n{caught}/{len(MUTATIONS)} mutation(s) caught")
    if survivors:
        print("\nThese behaviours can be removed without any test noticing:", file=sys.stderr)
        for label in survivors:
            print(f"  {label}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
