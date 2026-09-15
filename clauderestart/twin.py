"""Authenticating the windowed twin against the record embedded in this executable.

The console executable is the trust root for its quiet twin. build.py builds the twin
first, then embeds the twin's SHA-256 and size in the console build. At install time
the twin is opened with a handle that denies write and delete sharing, hashed through
that handle, and compared with the embedded record; the copy into Program Files then
reads the same handle, so the bytes that were checked are the bytes installed.

SHA256SUMS.txt is never consulted: it sits beside the executables in a folder the user
can write, so it can be replaced along with them.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

from . import payload, winapi
from .errors import RecoveryError, SafetyStop


@dataclass(frozen=True)
class EmbeddedTwin:
    """What the console build knows about its twin, fixed at build time."""

    name: str
    sha256: str
    size: int
    version: str


@dataclass
class AuthenticatedTwin:
    """A twin that matched the embedded record, still held open."""

    locked: winapi.LockedFile
    path: Path
    sha256: str
    size: int

    def close(self) -> None:
        self.locked.close()


_console_lock: winapi.LockedFile | None = None
_embedded: EmbeddedTwin | None = None
_embedded_loaded = False


def lock_console() -> winapi.LockedFile | None:
    """Open this executable so it cannot be replaced while the process runs.

    PyInstaller reads Python modules out of the executable by path on every import, so
    without this lock a process running as the same user could rename the file and swap
    in another build between two imports. The lock narrows that window to whatever was
    at the path when the user approved the elevation prompt.
    """
    global _console_lock
    if _console_lock is not None or not winapi.is_frozen():
        return _console_lock
    _console_lock = winapi.open_locked(Path(sys.executable).resolve())
    return _console_lock


def load_embedded_twin() -> EmbeddedTwin | None:
    """Return the record built into this executable, or None when there is none."""
    global _embedded, _embedded_loaded
    if _embedded_loaded:
        return _embedded
    _embedded_loaded = True
    try:
        from . import _twin  # type: ignore[attr-defined]
    except ImportError:
        _embedded = None
        return None
    digest = getattr(_twin, "TWIN_SHA256", None)
    if not digest:
        _embedded = None
        return None
    _embedded = EmbeddedTwin(
        name=str(getattr(_twin, "TWIN_NAME", payload.QUIET_EXE_NAME)),
        sha256=str(digest).lower(),
        size=int(getattr(_twin, "TWIN_SIZE", 0)),
        version=str(getattr(_twin, "TWIN_VERSION", "")),
    )
    return _embedded


def twin_candidates(console_path: Path) -> list[Path]:
    """The twin names to look for, in order. Only the first that exists is considered."""
    canonical_name = console_path.with_name(payload.QUIET_EXE_NAME)
    renamed = console_path.with_name(f"{console_path.stem}{payload.QUIET_EXE_SUFFIX}{console_path.suffix}")
    candidates = [canonical_name]
    if renamed != canonical_name:
        candidates.append(renamed)
    return candidates


def authenticate_twin(console_path: Path, *, embedded: EmbeddedTwin | None = None) -> AuthenticatedTwin:
    """Open and verify the quiet twin beside `console_path`, or stop.

    The first candidate name that exists is the only one opened; there is no fall back
    to a second file after a failed digest, because that second name is equally under
    the control of whoever placed the first.
    """
    if not winapi.is_frozen():
        raise RecoveryError("internal: authenticate_twin was called from a source run.")
    record = embedded if embedded is not None else load_embedded_twin()
    candidates = twin_candidates(console_path)
    names = ", ".join(candidate.name for candidate in candidates)
    if record is None:
        raise SafetyStop(
            "This build carries no record of its windowed twin, so the twin cannot be authenticated. "
            "Download the release again from the project's releases page."
        )
    present = [candidate for candidate in candidates if candidate.is_file()]
    if not present:
        raise SafetyStop(
            f"The windowed twin was not found beside {console_path.name} (looked for {names}). "
            "Extract the full release ZIP and install again. Nothing was changed."
        )
    target = present[0]
    try:
        locked = winapi.open_locked(target)
    except (RecoveryError, OSError) as exc:
        raise SafetyStop(
            f"{target.name} could not be opened for verification ({exc}). Another program may be using it; "
            "wait a moment and install again. Nothing was changed."
        ) from exc
    try:
        digest = hashlib.sha256()
        size = 0
        for chunk in locked.read_chunks():
            digest.update(chunk)
            size += len(chunk)
        observed = digest.hexdigest()
        if observed != record.sha256 or size != record.size:
            found_version = winapi.file_product_version(target)
            raise SafetyStop(
                f"{target.name} is not the windowed twin this build was made with, so it was not installed. "
                f"Expected SHA-256 {record.sha256} and {record.size} bytes; found {observed} and {size} bytes"
                + (f" (file reports version {found_version})" if found_version else "")
                + f". Candidates checked: {names}. Download the release again; nothing was changed."
            )
    except BaseException:
        locked.close()
        raise
    return AuthenticatedTwin(locked=locked, path=target, sha256=record.sha256, size=record.size)
