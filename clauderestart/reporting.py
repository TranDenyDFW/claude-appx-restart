"""Run reporting and the locations the tool logs to and relaunches from."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import sys

from . import payload, winapi


class Reporter:
    def __init__(self) -> None:
        self.lines: list[str] = []
        # Set to False only once an elevated child has actually written its own result,
        # so every way elevation can fail still leaves a diagnostic on disk.
        self.persist = True
        # A fingerprint of the log file taken before handing off, so this run never
        # replaces a log another run wrote in the meantime.
        self.log_guard: tuple | None = None

    def emit(self, state: str, message: str) -> None:
        line = f"[{state}] {message}"
        self.lines.append(line)
        if sys.stdout is not None:
            print(line, flush=True)

    def save(
        self,
        base: Path | None = None,
        fallback: Path | None = None,
        guard: tuple | None = None,
    ) -> Path | None:
        """Write the run log beside the tool; fall back to %LOCALAPPDATA%\\ClaudeRestart.

        With `guard` set to a fingerprint taken earlier, a log that changed since then
        belongs to another run of this tool, so these lines go to a second file rather
        than replacing it. Losing one diagnostic to save another helps nobody.
        """
        if not self.lines:
            return None
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        text = stamp + "\n" + "\n".join(self.lines) + "\n"
        root = base or app_location()
        target = root / payload.LOG_FILE_NAME
        if guard is not None and log_fingerprint(target) != guard:
            target = root / payload.PARENT_LOG_FILE_NAME
        try:
            target.write_text(text, encoding="utf-8")
            return target
        except OSError:
            root = fallback or log_fallback_dir()
            root.mkdir(parents=True, exist_ok=True)
            target = root / target.name
            target.write_text(text, encoding="utf-8")
            return target


def app_entry() -> Path:
    """Return the file a launcher must run: the frozen executable, else claude_restart.py.

    From source this is the entry script beside the package, never a module inside the
    package, so the elevated relaunch and a source task run the real entry point.
    """
    if winapi.is_frozen():
        return Path(sys.executable).resolve()
    return payload.SOURCE_ENTRY


def app_location() -> Path:
    return app_entry().parent


def log_fallback_dir() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    return (Path(root) if root else app_location()) / payload.LOG_FALLBACK_DIRNAME


def log_fingerprint(path: Path) -> tuple:
    """Identify a log file's current contents without reading them.

    No clock is involved: the question is only whether this file is still the one that
    was there before, which a file server with a skewed clock cannot confuse.
    """
    try:
        info = path.stat()
    except OSError:
        return (False, 0, 0, 0)
    return (True, int(info.st_size), int(info.st_mtime_ns), int(getattr(info, "st_ino", 0)))
