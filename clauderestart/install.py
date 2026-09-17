"""Installing the release into Program Files as an immutable version, and removing it.

Nothing is ever written over a file the live task refers to. Each install stages a new
folder inside the protected root, proves every staged file, renames the finished folder
into place, and only then points the task at it. A failure before that rename leaves the
previous version and the previous task exactly as they were.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets

from . import __version__
from . import package as package_module, payload, security, task as task_module, twin as twin_module, winapi
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
    try:
        path.mkdir()
    except FileExistsError as exc:
        # The identifier is random, so something else put this here. It is neither used nor
        # removed: this did not create it, and deleting another program's folder is not safe.
        raise SafetyStop(
            f"{path} already exists, so nothing was installed. Check what created it before "
            "removing it, then install again."
        ) from exc
    except OSError as exc:
        raise SafetyStop(f"{path} could not be created: {exc}") from exc
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
    except (RecoveryError, OSError) as exc:
        raise SafetyStop(f"{path} could not be corrected ({exc}). " + REMOVE_BY_HAND) from exc
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


def file_digest(path: Path) -> tuple[str, int]:
    """Return (sha256, size) for a file already on disk."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _copy_from_handle(locked: winapi.LockedFile, destination: Path) -> tuple[str, int]:
    """Copy an open file to a new path, hashing what is actually written.

    The source is the handle that was verified, not its pathname, so the bytes that
    were checked are the bytes that land in Program Files.
    """
    digest = hashlib.sha256()
    size = 0
    with open(destination, "xb") as out:  # x: never overwrite anything
        for chunk in locked.read_chunks():
            out.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _copy_path(source: Path, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(source, "rb") as reader, open(destination, "xb") as out:
        for chunk in iter(lambda: reader.read(1 << 20), b""):
            out.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class InstallManifest:
    """What one installed version consists of, written last and verified on every use."""

    def __init__(
        self,
        version: str,
        identifier: str,
        files: dict[str, dict[str, object]],
        embedded_twin: dict[str, object],
        created: str = "",
    ) -> None:
        self.version = version
        self.identifier = identifier
        self.files = files
        self.embedded_twin = embedded_twin
        self.created = created

    @classmethod
    def read(cls, folder: Path) -> "InstallManifest | None":
        path = folder / payload.MANIFEST_NAME
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or "files" not in data:
            return None
        return cls(
            str(data.get("version") or ""),
            str(data.get("id") or ""),
            dict(data.get("files") or {}),
            dict(data.get("embedded_twin") or {}),
            str(data.get("created") or ""),
        )

    def write(self, folder: Path) -> Path:
        path = folder / payload.MANIFEST_NAME
        path.write_text(
            json.dumps(
                {
                    "version": self.version,
                    "id": self.identifier,
                    "created": self.created,
                    "embedded_twin": self.embedded_twin,
                    "files": self.files,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def entries(self) -> list[tuple[str, str, int]]:
        return [
            (relative, str(entry.get("sha256") or ""), int(entry.get("size") or 0))
            for relative, entry in sorted(self.files.items())
        ]

    def verify(self, folder: Path) -> list[str]:
        """Return every recorded file that is missing or no longer matches."""
        problems: list[str] = []
        for relative, digest, size in self.entries():
            path = folder / relative
            if not _inside(folder, path):
                problems.append(f"{relative} points outside the install folder")
                continue
            if not path.is_file():
                problems.append(f"{relative} is missing")
                continue
            observed, observed_size = file_digest(path)
            if observed != digest or observed_size != size:
                problems.append(f"{relative} does not match what was installed")
        return problems


def _relative_key(relative: object) -> str:
    """One spelling for a path inside an install folder: forward slashes, lower case."""
    return str(relative).replace("\\", "/").lower()


def _inside(root: Path, candidate: Path) -> bool:
    """True when candidate really sits under root, after resolving both."""
    root_text = winapi.canonical(root)
    candidate_text = winapi.canonical(candidate)
    return candidate_text == root_text or candidate_text.startswith(root_text + os.sep)


def version_folders(root: Path) -> list[Path]:
    versions = versions_dir(root)
    if not versions.is_dir():
        return []
    return sorted(path for path in versions.iterdir() if path.is_dir())


def installed_version(folder: Path) -> str:
    """The version a folder holds: from its manifest, else from its name."""
    manifest = InstallManifest.read(folder)
    if manifest is not None and manifest.version:
        return manifest.version
    return folder.name.split("-", 1)[0].split(payload.STAGING_SUFFIX, 1)[0]


def _stage_payload(
    staging: Path, twin: twin_module.AuthenticatedTwin, console: winapi.LockedFile
) -> dict[str, dict[str, object]]:
    """Copy the release into the staging folder, recording what was actually written."""
    files: dict[str, dict[str, object]] = {}
    digest, size = _copy_from_handle(console, staging / payload.CONSOLE_EXE_NAME)
    files[payload.CONSOLE_EXE_NAME] = {"sha256": digest, "size": size}
    digest, size = _copy_from_handle(twin.locked, staging / payload.QUIET_EXE_NAME)
    files[payload.QUIET_EXE_NAME] = {"sha256": digest, "size": size}
    source = app_location()
    for relative in payload.SUPPORT_FILES:
        origin = source / relative
        if not origin.is_file():
            continue
        digest, size = _copy_path(origin, staging / relative)
        files[relative] = {"sha256": digest, "size": size}
    return files


def _verify_staged(staging: Path, manifest: InstallManifest, backend: security.FileSecurity, twin_sha: str) -> None:
    """Prove every staged file through a fresh handle before anything is committed."""
    problems = manifest.verify(staging)
    if problems:
        raise SafetyStop(f"The staged files in {staging} did not verify: " + "; ".join(problems))
    # The manifest keys use forward slashes, because that is how the payload names the
    # files it ships; a path from the filesystem uses backslashes. Compare one form.
    recorded = {_relative_key(relative) for relative, _digest, _size in manifest.entries()}
    for path in staging.rglob("*"):
        if path.is_dir():
            continue
        relative = _relative_key(path.relative_to(staging))
        if relative == _relative_key(payload.MANIFEST_NAME):
            continue
        if relative not in recorded:
            raise SafetyStop(f"{path} appeared in the staged files but is not part of this release.")
    for relative, digest, _size in manifest.entries():
        locked = winapi.open_locked(staging / relative, open_reparse_point=True)
        try:
            if locked.is_reparse_point():
                raise SafetyStop(f"{relative} in {staging} is a reparse point.")
            if not locked.final_path().startswith(winapi.canonical(staging)):
                raise SafetyStop(f"{relative} in {staging} resolves outside the staged folder.")
            report = backend.verify_child(locked)
            if not report.ok:
                raise SafetyStop(f"{relative} in {staging} has unexpected permissions: " + "; ".join(report.problems))
            if relative == payload.QUIET_EXE_NAME and digest != twin_sha:
                raise SafetyStop("The staged windowed executable is not the one this build was made with.")
        finally:
            locked.close()


def _commit_staging(staging: Path, final: Path, reporter: Reporter) -> None:
    """Rename the finished folder into place, retrying only a sharing conflict."""
    last: OSError | None = None
    for attempt in range(1, 4):
        try:
            os.rename(staging, final)
            return
        except PermissionError as exc:
            last = exc
            reporter.emit(
                "RETRY",
                f"Could not put the new version in place yet (attempt {attempt} of 3); "
                "antivirus may still be reading the new files.",
            )
        except OSError as exc:
            last = exc
            break
    raise RecoveryError(
        f"Could not put the new version in place ({last}). Nothing was changed; wait a minute and install again."
    )


def install_versioned(
    reporter: Reporter,
    twin: twin_module.AuthenticatedTwin,
    package: package_module.PackageInfo,
    *,
    backend: security.FileSecurity | None = None,
    tasks: task_module.TaskBackend | None = None,
    root: Path | None = None,
    allow_downgrade: bool = False,
) -> Path:
    """Install this release as a new immutable version and point the task at it."""
    backend = backend or security.WindowsFileSecurity()
    tasks = tasks or task_module.WindowsTaskBackend()
    console = twin_module.console_lock()
    if console is None:
        raise RecoveryError("internal: the running executable was not locked at startup.")

    # Ask Task Scheduler first: a lookup that fails then stops the install before the root is
    # created or its permissions are repaired.
    before = tasks.automation_task_status()
    root = verify_root(reporter, backend, root)
    had_task = before.get("Installed") is True
    previous_xml = None
    if had_task:
        current = task_module.task_command_path(before.get("Execute"))
        _refuse_downgrade(current, root, allow_downgrade)
        previous_xml = tasks.export_task_xml()

    identifier = secrets.token_hex(4)
    staging = versions_dir(root) / f"{__version__}{payload.STAGING_SUFFIX}-{identifier}"
    final = versions_dir(root) / f"{__version__}-{identifier}"
    _create_owned_dir(staging, backend, reporter)
    try:
        files = _stage_payload(staging, twin, console)
        manifest = InstallManifest(
            __version__,
            identifier,
            files,
            {"name": twin.path.name, "sha256": twin.sha256, "size": twin.size},
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        manifest.write(staging)
        _verify_staged(staging, manifest, backend, twin.sha256)
    except BaseException:
        _discard(staging)
        raise

    try:
        _commit_staging(staging, final, reporter)
    except BaseException:
        # Otherwise the error says nothing was changed while the whole payload sits in
        # Program Files under a staging name.
        _discard(staging)
        raise
    quiet = final / payload.QUIET_EXE_NAME
    locked = winapi.open_locked(quiet, open_reparse_point=True)
    try:
        _verify_committed(final, locked, manifest, backend, twin.sha256)
        reporter.emit(
            "COPIED",
            f"Installed {len(manifest.files)} file(s) into {final}, which only administrators can change.",
        )
        _register_and_verify(reporter, tasks, quiet, package, final, previous_xml, had_task, locked)
    except BaseException:
        locked.close()
        _mark_broken(final)
        raise
    locked.close()

    cleanup_versions(reporter, root, keep=final)
    _remove_legacy_layout(reporter, root, quiet)
    return final


def _refuse_downgrade(current: Path, root: Path, allow_downgrade: bool) -> None:
    """Stop an older release from replacing a newer installed one by accident."""
    if allow_downgrade or not _inside(versions_dir(root), current):
        return
    folder = current.parent
    installed = installed_version(folder)
    try:
        newer = package_module.version_key(installed + ".0") > package_module.version_key(__version__ + ".0")
    except SafetyStop:
        return
    if newer:
        raise SafetyStop(
            f"Automatic recovery already runs version {installed}, which is newer than this installer "
            f"({__version__}). Nothing was changed; pass --allow-downgrade to replace it deliberately."
        )


def _verify_committed(
    final: Path,
    locked: winapi.LockedFile,
    manifest: InstallManifest,
    backend: security.FileSecurity,
    twin_sha: str,
) -> None:
    """Re-prove the committed folder through fresh handles, after the rename."""
    directory = _open_owned_dir(final)
    try:
        if directory.is_reparse_point() or directory.final_path() != winapi.canonical(final):
            raise SafetyStop(f"{final} did not resolve to itself after it was put in place.")
        folder_report = backend.verify_owned_dir(directory)
    finally:
        directory.close()
    if not folder_report.ok:
        raise SafetyStop(
            f"{final} is not administrator-only after the rename: " + "; ".join(folder_report.problems)
        )
    if locked.is_reparse_point() or locked.final_path() != winapi.canonical(final / payload.QUIET_EXE_NAME):
        raise SafetyStop(f"{final} did not resolve to itself after it was put in place.")
    digest = hashlib.sha256()
    for chunk in locked.read_chunks():
        digest.update(chunk)
    if digest.hexdigest() != twin_sha:
        raise SafetyStop(f"The installed windowed executable in {final} is not the authenticated one.")
    report = backend.verify_child(locked)
    if not report.ok:
        raise SafetyStop("The installed executable has unexpected permissions: " + "; ".join(report.problems))
    problems = manifest.verify(final)
    if problems:
        raise SafetyStop(f"The installed files in {final} did not verify: " + "; ".join(problems))


def _register_and_verify(
    reporter: Reporter,
    tasks: task_module.TaskBackend,
    quiet: Path,
    package: package_module.PackageInfo,
    final: Path,
    previous_xml: str | None,
    had_task: bool,
    locked: winapi.LockedFile,
) -> None:
    """Register the task, then verify it, restoring the previous definition on failure."""
    arguments = task_module.TASK_ARGUMENTS
    try:
        tasks.register_task_xml(task_module.build_task_xml(quiet, arguments, package.user_sid, final))
        status = tasks.automation_task_status()
        problems = task_module.verify_registered_task(status, arguments, quiet)
        if not problems:
            registered = task_module.task_command_path(status.get("Execute"))
            check = winapi.open_locked(registered, open_reparse_point=True)
            try:
                if not os.path.samestat(check.stat(), locked.stat()):
                    problems.append("the registered task runs a different file from the one installed")
            finally:
                check.close()
        if problems:
            raise SafetyStop("The registered task was not what was asked for: " + "; ".join(problems))
    except BaseException as exc:
        _restore_task(reporter, tasks, previous_xml, had_task, exc)
        raise
    reporter.emit(
        "INSTALLED",
        f"Task '{task_module.AUTO_RECOVERY_TASK_NAME}' watches Event 208 for "
        f"{package_module.AUTO_RECOVERY_APPLICATION}, runs only while this user is signed in, and also runs "
        "on battery power.",
    )
    reporter.emit("ACTION", task_module.build_task_action(quiet, arguments))
    reporter.emit("PACKAGE", f"Current package verified: {package.package_full_name}")


def _restore_task(
    reporter: Reporter,
    tasks: task_module.TaskBackend,
    previous_xml: str | None,
    had_task: bool,
    cause: BaseException,
) -> None:
    """Put the previous task back, or remove the one just registered."""
    try:
        if had_task and previous_xml:
            tasks.register_task_xml(previous_xml)
            reporter.emit("RESTORED", "The previous automatic recovery task was put back unchanged.")
        else:
            completed = tasks.delete_task()
            if completed.returncode == 0:
                reporter.emit("RESTORED", "The task registered by this run was removed again.")
            # schtasks also fails when there is nothing to delete, as after a registration it
            # refused, so a failed delete is an error only while the task is still registered.
            elif tasks.automation_task_status().get("Installed") is False:
                reporter.emit("RESTORED", "No task from this run is left registered.")
            else:
                detail = (completed.stderr or completed.stdout).strip()
                raise RecoveryError(f"schtasks could not delete it ({completed.returncode}): {detail}")
    except (RecoveryError, OSError) as exc:
        reporter.emit(
            "ERROR",
            f"The task could not be restored after {cause}: {exc}. Run Remove Automatic Recovery, then install again.",
        )


def _discard(staging: Path) -> None:
    """Remove a staging folder and everything this run put in it."""
    if not staging.is_dir():
        return
    for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            path.unlink() if path.is_file() else path.rmdir()
        except OSError:
            pass
    _remove_empty(staging)


def _mark_broken(final: Path) -> None:
    """Move a committed folder aside when it failed its checks, so nothing runs it."""
    try:
        os.rename(final, final.with_name(final.name + payload.BROKEN_SUFFIX))
    except OSError:
        pass


def cleanup_versions(
    reporter: Reporter,
    root: Path,
    *,
    keep: Path | None = None,
    force: bool = False,
) -> None:
    """Remove other installed versions, keeping anything that is not ours or in use.

    This never raises: a previous version still in use is a retry, not a failure, and an
    unrecognised file is reported and kept.
    """
    running = winapi.canonical(app_entry())
    for folder in version_folders(root):
        if keep is not None and winapi.canonical(folder) == winapi.canonical(keep):
            continue
        if running.startswith(winapi.canonical(folder) + os.sep):
            reporter.emit("RETRY", f"{folder} is the version running now, so it was left in place.")
            continue
        _remove_version_folder(reporter, folder, force=force)


def _remove_version_folder(reporter: Reporter, folder: Path, *, force: bool) -> None:
    manifest = InstallManifest.read(folder)
    if manifest is None:
        reporter.emit("NOTE", f"{folder} has no installation record, so it was left in place.")
        return
    kept: list[str] = []
    for relative, digest, size in manifest.entries():
        path = folder / relative
        if not _inside(folder, path):
            kept.append(f"{relative} (points outside the folder)")
            continue
        if not path.is_file():
            continue
        observed, observed_size = file_digest(path)
        if (observed, observed_size) != (digest, size) and not force:
            kept.append(f"{relative} (changed since it was installed)")
            continue
        try:
            path.unlink()
        except OSError as exc:
            reporter.emit("RETRY", f"{path} is still in use ({exc}); run the installer again later.")
            return
    for extra in (payload.MANIFEST_NAME, payload.LOG_FILE_NAME):
        try:
            (folder / extra).unlink(missing_ok=True)
        except OSError:
            pass
    leftovers = sorted(path for path in folder.rglob("*") if path.is_file())
    if leftovers or kept:
        reporter.emit(
            "NOTE",
            f"{folder} was kept: " + "; ".join(kept + [str(path.relative_to(folder)) for path in leftovers]),
        )
        return
    for path in sorted(folder.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        _remove_empty(path)
    _remove_empty(folder)
    if not folder.exists():
        reporter.emit("REMOVED", f"Removed the previous version in {folder}.")


def _remove_legacy_layout(reporter: Reporter, root: Path, quiet: Path) -> None:
    """Remove the flat v1.0.2 files, once the task no longer refers to them."""
    legacy_quiet = root / payload.QUIET_EXE_NAME
    if winapi.canonical(quiet) == winapi.canonical(legacy_quiet):
        return
    removed = 0
    for relative in payload.LEGACY_ROOT_FILES:
        path = root / relative
        if not path.is_file():
            continue
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            reporter.emit("RETRY", f"{path} is still in use ({exc}); run the installer again later.")
            return
    for relative in payload.LEGACY_ROOT_DIRS:
        _remove_empty(root / relative)
    if removed:
        reporter.emit("REMOVED", f"Removed {removed} file(s) from the previous flat installation in {root}.")


def remove_installation(
    reporter: Reporter,
    root: Path | None = None,
    *,
    backend: security.FileSecurity | None = None,
    force: bool = False,
) -> None:
    """Remove every file this installer recorded, and nothing else."""
    backend = backend or security.WindowsFileSecurity()
    root = root or install_dir()
    if not root.is_dir():
        return
    problems = security.scan_tree(root, backend)
    if problems:
        raise SafetyStop(f"{root} cannot be trusted, so nothing was deleted: " + "; ".join(problems[:5]))
    running = winapi.canonical(app_entry())
    for folder in version_folders(root):
        if running.startswith(winapi.canonical(folder) + os.sep):
            reporter.emit(
                "NOTE",
                f"{folder} was left in place because this program is running from it; delete that folder to "
                "finish uninstalling.",
            )
            continue
        _remove_version_folder(reporter, folder, force=force)
    # Nothing is being installed here, so no executable is exempt from the legacy sweep
    # except one this very process is running.
    running_in_root = Path(running) if running.startswith(winapi.canonical(root) + os.sep) else Path("none")
    _remove_legacy_layout(reporter, root, running_in_root)
    _remove_empty(versions_dir(root))
    _remove_empty(root)
    if root.exists():
        reporter.emit("NOTE", f"Removed the installed files; {root} still holds other files, so it was kept.")
    else:
        reporter.emit("REMOVED", f"Deleted {root}.")


def install_from_source(
    reporter: Reporter,
    package: package_module.PackageInfo,
    *,
    tasks: task_module.TaskBackend | None = None,
) -> None:
    """Register the task to run this checkout, with the same rollback rules.

    A source install copies nothing into Program Files, so it carries the warning that
    the files it runs sit wherever the checkout is.
    """
    tasks = tasks or task_module.WindowsTaskBackend()
    reporter.emit(
        "WARN",
        "Running from source, so the task runs this interpreter and script from where they are now. "
        "Install with the release executables to run automatic recovery from Program Files, where only "
        "administrators can change the files it runs.",
    )
    executable, arguments = task_module.task_launcher()
    location = app_location()
    before = tasks.automation_task_status()
    had_task = before.get("Installed") is True
    previous_xml = tasks.export_task_xml() if had_task else None
    try:
        tasks.register_task_xml(task_module.build_task_xml(executable, arguments, package.user_sid, location))
        status = tasks.automation_task_status()
        problems = task_module.verify_registered_task(status, arguments, executable)
        if problems:
            raise SafetyStop("The registered task was not what was asked for: " + "; ".join(problems))
    except BaseException as exc:
        _restore_task(reporter, tasks, previous_xml, had_task, exc)
        raise
    reporter.emit(
        "INSTALLED",
        f"Task '{task_module.AUTO_RECOVERY_TASK_NAME}' watches Event 208 for "
        f"{package_module.AUTO_RECOVERY_APPLICATION} and runs only while this user is signed in.",
    )
    reporter.emit("ACTION", task_module.build_task_action(executable, arguments))
    reporter.emit("PACKAGE", f"Current package verified: {package.package_full_name}")


def installed_state(reporter: Reporter, root: Path | None = None) -> None:
    """Report what is installed and whether the task runs a protected file.

    Read only, and it never raises: this is what a user runs to find out what is wrong.
    """
    root = root or install_dir()
    if not root.is_dir():
        reporter.emit("ROOT", f"not installed ({root} is absent)")
        return
    try:
        locked = _open_owned_dir(root)
        try:
            report = security.WindowsFileSecurity().verify_owned_dir(locked)
            reparse = locked.is_reparse_point()
        finally:
            locked.close()
        if reparse:
            reporter.emit("ROOT", f"{root} is a junction or symbolic link")
        elif report.ok:
            reporter.emit("ROOT", f"{root} is administrator-only")
        else:
            reporter.emit("ROOT", f"{root}: " + "; ".join(report.problems))
    except (RecoveryError, OSError) as exc:
        reporter.emit("ROOT", f"{root}: permissions unreadable ({exc})")
    for folder in version_folders(root):
        manifest = InstallManifest.read(folder)
        if manifest is None:
            reporter.emit("VERSION", f"{folder.name}: no installation record")
            continue
        problems = manifest.verify(folder)
        state = "verified" if not problems else "; ".join(problems[:3])
        reporter.emit("VERSION", f"{folder.name} ({manifest.version}): {state}")
