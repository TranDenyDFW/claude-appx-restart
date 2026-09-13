#!/usr/bin/env python3
"""Build ClaudeRestart.exe and ClaudeRestart-quiet.exe with PyInstaller.

Steps: install the pinned build tools (unless --no-install), run the unit tests,
regenerate the icon, run PyInstaller on ClaudeRestart.spec, smoke-test both
executables, then zip the release layout into dist/. Windows, Python 3.10+.
read_version() is the single place the version is read from claude_restart.py;
ClaudeRestart.spec imports it from here.

    py -3 build.py
    py -3 build.py --no-install --skip-tests
    py -3 build.py --check-tag v1.0.0     # only verifies the tag matches __version__
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
SOURCE = ROOT / "claude_restart.py"
EXECUTABLES = ("ClaudeRestart.exe", "ClaudeRestart-quiet.exe")
RELEASE_FILES = (
    "ClaudeRestart-launch.cmd",
    "Install Automatic Recovery.cmd",
    "Remove Automatic Recovery.cmd",
    "Start Claude Safely.cmd",
    "README.md",
    "docs/windows-event-automation.md",
)


def read_version() -> str:
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', SOURCE.read_text(encoding="utf-8"), re.M)
    if not match:
        sys.exit("__version__ not found in claude_restart.py")
    return match.group(1)


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    print("+", subprocess.list2cmdline(command), flush=True)
    return subprocess.run(command, cwd=ROOT, check=True, text=True, **kwargs)  # type: ignore[call-overload]


def smoke_test(dist: Path, expected_version: str) -> None:
    """Exercise both executables; exit with a message on any failure.

    The console build must print the expected version and pass --self-check. The
    windowed build has no console output, so it is judged by its exit code and by the
    last-run.log it must write beside itself.
    """
    console_exe = dist / EXECUTABLES[0]
    quiet_exe = dist / EXECUTABLES[1]
    for name in EXECUTABLES:
        if not (dist / name).is_file():
            sys.exit(f"PyInstaller did not produce {name}.")
    shown = run([str(console_exe), "--version"], capture_output=True).stdout.strip()
    if expected_version not in shown:
        sys.exit(f"Smoke test failed: '{shown}' does not contain {expected_version}.")
    run([str(console_exe), "--self-check"])
    log = dist / "last-run.log"
    if log.is_file():
        log.unlink()
    print("+", subprocess.list2cmdline([str(quiet_exe), "--self-check"]), "(windowed, no output expected)", flush=True)
    quiet = subprocess.run([str(quiet_exe), "--self-check"], cwd=ROOT, check=False)
    if quiet.returncode != 0:
        sys.exit(f"Smoke test failed: {quiet_exe.name} --self-check exited {quiet.returncode}.")
    if not log.is_file() or "SELF-CHECK" not in log.read_text(encoding="utf-8"):
        sys.exit(f"Smoke test failed: {quiet_exe.name} did not write {log.name} beside itself.")
    print(log.read_text(encoding="utf-8").strip().splitlines()[-1], flush=True)
    log.unlink()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the ClaudeRestart executables.")
    parser.add_argument("--no-install", action="store_true", help="do not pip install requirements-build.txt")
    parser.add_argument("--skip-tests", action="store_true", help="do not run the unit tests first")
    parser.add_argument("--skip-icon", action="store_true", help="do not regenerate assets/ClaudeRestart.ico")
    parser.add_argument("--check-tag", metavar="TAG", help="exit 1 unless TAG equals 'v' + __version__, then stop")
    args = parser.parse_args()

    current = read_version()
    if args.check_tag is not None:
        expected = f"v{current}"
        if args.check_tag != expected:
            sys.exit(f"Tag {args.check_tag!r} does not match __version__ ({expected}).")
        print(f"Tag {args.check_tag} matches __version__.")
        return 0

    if os.name != "nt":
        sys.exit("The executables can only be built on Windows.")
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required.")

    python = sys.executable
    if not args.no_install:
        run([python, "-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements-build.txt"])
    if not args.skip_tests:
        run([python, "-m", "unittest", "discover", "-s", "tests", "-v"])
    if not args.skip_icon:
        run([python, str(ROOT / "tools" / "make_icon.py")])

    for stale in (DIST, ROOT / "build"):
        shutil.rmtree(stale, ignore_errors=True)
    run([python, "-m", "PyInstaller", "--clean", "--noconfirm", str(ROOT / "ClaudeRestart.spec")])

    smoke_test(DIST, current)

    archive = DIST / f"ClaudeRestart-v{current}-win-x64.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in EXECUTABLES:
            bundle.write(DIST / name, name)
        for relative in RELEASE_FILES:
            bundle.write(ROOT / relative, relative)

    checksums = DIST / "SHA256SUMS.txt"
    lines = [f"{sha256(DIST / name)}  {name}" for name in (*EXECUTABLES, archive.name)]
    checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nBuilt {archive}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
