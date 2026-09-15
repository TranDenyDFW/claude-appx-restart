"""Installing the release into Program Files and removing it again."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil

from . import payload, winapi
from .errors import RecoveryError
from .reporting import Reporter, app_entry, app_location


def install_dir() -> Path:
    return winapi.program_files_dir() / payload.INSTALL_DIRNAME


def _same_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_layout() -> list[tuple[Path, str, bool]]:
    """Return (source file, path inside the install folder, required) for the running release."""
    console = app_entry()
    twin = console.with_name(f"{console.stem}{payload.QUIET_EXE_SUFFIX}{console.suffix}")
    layout = [(console, payload.CONSOLE_EXE_NAME, True), (twin, payload.QUIET_EXE_NAME, True)]
    layout.extend((console.parent / relative, relative, False) for relative in payload.INSTALL_SUPPORT_FILES)
    return layout


def copy_to_install_dir(reporter: Reporter, target: Path) -> Path:
    """Copy the running release into target and return it; nothing is copied if a check fails."""
    source = app_location()
    if _same_path(source, target):
        for name in (payload.CONSOLE_EXE_NAME, payload.QUIET_EXE_NAME):
            if not (target / name).is_file():
                raise RecoveryError(f"{name} is missing from {target}; reinstall from the full release ZIP.")
        reporter.emit("LOCATION", f"Already running from {target}; no files to copy.")
        return target
    layout = install_layout()
    for source_file, relative, required in layout:
        if required and not source_file.is_file():
            raise RecoveryError(
                f"{source_file.name} was not found beside {app_entry().name}; extract the full release ZIP "
                "and install again. Nothing was changed."
            )
    copied = 0
    for source_file, relative, _required in layout:
        if not source_file.is_file():
            continue
        destination = target / relative
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, destination)
        except OSError as exc:
            raise RecoveryError(
                f"Could not copy {relative} into {target}: {exc}. If automatic recovery is running right "
                "now, wait a minute and install again."
            ) from exc
        if _file_sha256(source_file) != _file_sha256(destination):
            raise RecoveryError(f"The copy of {relative} in {target} does not match the original; install again.")
        copied += 1
    reporter.emit("COPIED", f"Installed {copied} file(s) into {target}, which only administrators can change.")
    reporter.emit("NOTE", f"Automatic recovery no longer uses {source}; you can delete that folder.")
    return target


def remove_install_dir(reporter: Reporter, target: Path) -> None:
    """Delete the files --install-automation placed in target, leaving anything else untouched."""
    if not target.is_dir():
        return
    if _same_path(app_location(), target):
        reporter.emit(
            "NOTE",
            f"{target} was left in place because this program is running from it; "
            "delete that folder to finish uninstalling.",
        )
        return
    problems: list[str] = []
    relatives = [
        payload.CONSOLE_EXE_NAME,
        payload.QUIET_EXE_NAME,
        *payload.INSTALL_SUPPORT_FILES,
        payload.LOG_FILE_NAME,
    ]
    for relative in relatives:
        path = target / relative
        try:
            if path.is_file():
                path.unlink()
        except OSError as exc:
            problems.append(f"{relative}: {exc}")
    subfolders = {(target / relative).parent for relative in relatives} - {target}
    for folder in sorted(subfolders, key=lambda item: len(item.parts), reverse=True):
        try:
            folder.rmdir()
        except OSError:
            pass
    try:
        target.rmdir()
    except OSError:
        pass
    if problems:
        reporter.emit("WARN", f"Could not delete some files in {target}: " + "; ".join(problems))
    elif target.exists():
        reporter.emit("NOTE", f"Removed the installed files; {target} still holds other files, so it was kept.")
    else:
        reporter.emit("REMOVED", f"Deleted {target}.")
