"""The release and install payload, defined once.

build.py, ClaudeRestart.spec, the installer, and the tests import these names, so
adding a file to the release cannot create two diverging manifests. Pure Python:
no Windows imports, safe to import on any platform.
"""

from __future__ import annotations

from pathlib import Path


CONSOLE_EXE_NAME = "ClaudeRestart.exe"
QUIET_EXE_NAME = "ClaudeRestart-quiet.exe"
QUIET_EXE_SUFFIX = "-quiet"
EXECUTABLES = (CONSOLE_EXE_NAME, QUIET_EXE_NAME)

LAUNCHER_FILES = (
    "ClaudeRestart-launch.cmd",
    "Install Automatic Recovery.cmd",
    "Remove Automatic Recovery.cmd",
    "Start Claude Safely.cmd",
)
DOC_FILES = (
    "README.md",
    "docs/windows-event-automation.md",
)
# Non-executable files shipped in the release ZIP beside the executables.
RELEASE_FILES = LAUNCHER_FILES + DOC_FILES
CHECKSUMS_NAME = "SHA256SUMS.txt"

# v1.0.2 install layout (flat, directly inside the install folder).
INSTALL_SUPPORT_FILES = LAUNCHER_FILES + ("README.md", CHECKSUMS_NAME, "docs/windows-event-automation.md")

INSTALL_DIRNAME = "ClaudeRestart"
LOG_FILE_NAME = "last-run.log"
LOG_FALLBACK_DIRNAME = "ClaudeRestart"

TASK_NAME = "Claude AppX Auto-Recovery"
TASK_ARGUMENTS = "--event-triggered --yes --wait 30"

# The entry script the source launchers, the elevated relaunch, and a source task run.
SOURCE_ENTRY = Path(__file__).resolve().parents[1] / "claude_restart.py"


def release_zip_name(version: str) -> str:
    return f"ClaudeRestart-v{version}-win-x64.zip"


def release_asset_names(version: str) -> tuple[str, ...]:
    """Every asset a GitHub release for `version` must carry, and nothing else."""
    return (release_zip_name(version), CONSOLE_EXE_NAME, QUIET_EXE_NAME, CHECKSUMS_NAME)
