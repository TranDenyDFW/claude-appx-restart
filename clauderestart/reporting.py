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
        # False while this process only hands off to an elevated child, so the child's
        # last-run.log is not overwritten by the parent's hand-off lines.
        self.persist = True

    def emit(self, state: str, message: str) -> None:
        line = f"[{state}] {message}"
        self.lines.append(line)
        if sys.stdout is not None:
            print(line, flush=True)

    def save(self, base: Path | None = None, fallback: Path | None = None) -> Path | None:
        """Write the run log beside the tool; fall back to %LOCALAPPDATA%\\ClaudeRestart."""
        if not self.lines:
            return None
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        text = stamp + "\n" + "\n".join(self.lines) + "\n"
        target = (base or app_location()) / payload.LOG_FILE_NAME
        try:
            target.write_text(text, encoding="utf-8")
            return target
        except OSError:
            root = fallback or log_fallback_dir()
            root.mkdir(parents=True, exist_ok=True)
            target = root / payload.LOG_FILE_NAME
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
