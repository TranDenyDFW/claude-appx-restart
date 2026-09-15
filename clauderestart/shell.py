"""Child-process helpers (a leaf module: imports only clauderestart.errors)."""

from __future__ import annotations

import os
import subprocess

from .errors import RecoveryError


CREATE_NO_WINDOW = 0x08000000
# Every child process (PowerShell, schtasks, explorer) is spawned without a console so an
# event-triggered run under pythonw.exe / ClaudeRestart-quiet.exe never flashes a window.
NO_WINDOW: dict[str, int] = {"creationflags": CREATE_NO_WINDOW} if os.name == "nt" else {}


def run_powershell(script: str, timeout: int = 30) -> str:
    utf8 = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "$OutputEncoding = [Console]::OutputEncoding; "
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", utf8 + script],
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=timeout,
        check=False,
        **NO_WINDOW,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"PowerShell query failed ({completed.returncode}): {detail}")
    return completed.stdout.strip()


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
