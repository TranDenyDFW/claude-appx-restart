"""Installing the release into Program Files and removing it again."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil

from . import payload, security, winapi
from .errors import RecoveryError, SafetyStop
from .reporting import Reporter, app_entry, app_location


REMOVE_BY_HAND = (
    "Delete that folder by hand and install again; this installer will not change a folder "
    "another account can alter while it works."
)


def install_dir() -> Path:
    return winapi.program_files_dir() / payload.INSTALL_DIRNAME


def versions_dir(root: Path | None = None) -> Path:
    return (root or install_dir()) / payload.VERSIONS_DIRNAME


def _open_owned_dir(path: Path) -> winapi.LockedFile:
    """Open a folder for inspection: the link itself, never what it points at."""
    return winapi.open_locked(
        path,
        directory=True,
        open_reparse_point=True,
        share=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
    )


def _remove_empty(path: Path) -> None:
    try:
        path.rmdir()
    except OSError:
        pass


def _create_owned_dir(path: Path, backend: security.FileSecurity, reporter: Reporter) -> None:
    """Create a folder this installer owns, protect it, and prove it, or leave nothing."""
    path.mkdir()
    try:
        locked = security.open_for_repair(path)
        try:
            if locked.is_reparse_point() or locked.final_path() != winapi.canonical(path):
                raise SafetyStop(f"{path} did not resolve to itself straight after it was created.")
            backend.apply_owned_dir(locked)
            report = backend.verify_owned_dir(locked)
        finally:
            locked.close()
    except SafetyStop:
        _remove_empty(path)
        raise
    except (RecoveryError, OSError) as exc:
        # Nothing was installed, so this is a stop, not a half-finished install.
        _remove_empty(path)
        raise SafetyStop(f"{path} could not be made administrator-only: {exc}") from exc
    except BaseException:
        _remove_empty(path)
        raise
    if not report.ok:
        _remove_empty(path)
        raise SafetyStop(f"{path} could not be made administrator-only: " + "; ".join(report.problems))
    reporter.emit("PROTECTED", f"Created {path}; only administrators can change it.")


def _verify_owned_dir(path: Path, backend: security.FileSecurity, reporter: Reporter) -> None:
    """Prove an existing folder is administrator-only, repairing it when that is safe."""
    locked = _open_owned_dir(path)
    try:
        if locked.is_reparse_point():
            raise SafetyStop(f"{path} is a junction, symbolic link, or other reparse point. " + REMOVE_BY_HAND)
        if locked.final_path() != winapi.canonical(path):
            raise SafetyStop(f"{path} resolves to {locked.final_path()}. " + REMOVE_BY_HAND)
        report = backend.verify_owned_dir(locked)
    finally:
        locked.close()
    if report.ok:
        return
    if report.blocking:
        raise SafetyStop(
            f"{path} is not administrator-only: " + "; ".join(report.blocking) + ". " + REMOVE_BY_HAND
        )
    reporter.emit("REPAIR", f"{path} needs its permissions corrected: " + "; ".join(report.problems))
    locked = security.open_for_repair(path)
    try:
        backend.apply_owned_dir(locked)
        report = backend.verify_owned_dir(locked)
    finally:
        locked.close()
    if not report.ok:
        raise SafetyStop(f"{path} could not be corrected: " + "; ".join(report.problems) + ". " + REMOVE_BY_HAND)
    reporter.emit("PROTECTED", f"{path} is administrator-only.")


def verify_root(reporter: Reporter, backend: security.FileSecurity | None = None, root: Path | None = None) -> Path:
    """Return an install root proven to be administrator-only, creating it when absent.

    Everything is checked before anything is written. A reparse point anywhere in the
    tree, a hard-linked file, or any folder another account can write stops the install:
    that account could swap a checked path for another between the check and the copy.
    """
    backend = backend or security.WindowsFileSecurity()
    root = root or install_dir()
    program_files = root.parent
    locked = _open_owned_dir(program_files)
    try:
        if locked.is_reparse_point() or locked.final_path() != winapi.canonical(program_files):
            raise SafetyStop(f"{program_files} is not the real Program Files folder; nothing was changed.")
    finally:
        locked.close()

    if not root.exists():
        _create_owned_dir(root, backend, reporter)
    else:
        problems = security.scan_tree(root, backend)
        if problems:
            raise SafetyStop(f"{root} cannot be trusted: " + "; ".join(problems[:5]) + ". " + REMOVE_BY_HAND)
        _verify_owned_dir(root, backend, reporter)

    versions = versions_dir(root)
    if not versions.exists():
        _create_owned_dir(versions, backend, reporter)
    else:
        _verify_owned_dir(versions, backend, reporter)
    return root


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
