#!/usr/bin/env python3
"""Safely repair Claude Desktop's stale AppX Job and start Claude.

This utility targets one verified failure mode: Appinfo retaining a versioned
Container_Claude Job from an older installed package. It never searches for or
kills processes by executable name. Instead, it duplicates the exact kernel
Job handle held by Appinfo, displays the Job's current members, terminates that
Job only when its identity and older version are unambiguous, then launches and
verifies the currently installed Claude package.

This file is the entry script; the implementation lives in the clauderestart
package beside it, so a source install needs this file and that folder. PyInstaller
freezes both into ClaudeRestart.exe (console) and ClaudeRestart-quiet.exe (windowed
twin used by the scheduled task); see build.py.

Python 3.10+; Windows only; no third-party packages.
"""

from __future__ import annotations

from clauderestart.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
