# Start Claude when Windows says a file is in use

Claude Restart fixes the Claude Desktop error **Another program is currently using this file**. Install automatic recovery once and keep using your normal Claude shortcut, or run the manual launcher whenever Claude fails to open.

## Before you start

You need:

- Windows 10 or Windows 11
- [Python 3.10 or newer](https://www.python.org/downloads/windows/)
- The Microsoft Store build of Claude Desktop

## Install automatic recovery

Automatic recovery runs after Windows detects this exact Claude startup error. You don't need to keep another app open.

1. [Download the repository as a ZIP](https://github.com/TranDenyDFW/claude-appx-restart/archive/refs/heads/main.zip).
2. Extract the ZIP file.
3. Double-click **Install Automatic Recovery.cmd**.
4. Approve the Windows User Account Control (UAC) prompt.
5. Open Claude from your normal shortcut.

Windows creates a Scheduled Task named `Claude AppX Auto-Recovery`. When the error occurs, the task closes only the verified obsolete Claude Job and opens the installed version of Claude.

The error dialog can appear briefly because Windows records the failure before automatic recovery starts.

## Start Claude without automatic recovery

Double-click **Start Claude Safely.cmd** and approve the UAC prompt. The launcher checks for an obsolete Claude Job before opening Claude, so the error dialog should not appear.

The launcher prints `GREEN` after it finds a visible Claude window and confirms that Windows recorded no new `0x80070020` errors.

## Remove automatic recovery

Double-click **Remove Automatic Recovery.cmd** and approve the UAC prompt. This removes the Scheduled Task without changing Claude or Python.

## Check the status or recent errors

Open PowerShell in the extracted folder, then run one of these commands:

```powershell
# Check automatic recovery status
py -3 .\claude_restart.py --automation-status

# Find this Claude startup error in the last 180 minutes
py -3 .\claude_restart.py --trace --minutes 180

# Scan for an obsolete Claude Job without closing anything
py -3 .\claude_restart.py --scan
```

The script writes the latest result to `last-run.log` beside the script.

## What the tool can close

The tool identifies the installed Claude package, then inspects the Windows Job objects held by the Application Information (`Appinfo`) service. It closes a Job only when its package version is older than the installed Claude version.

The tool stops without making changes when it finds a current version, another user, another Windows session, a newer version, or an unexpected package identity. It does not kill processes by executable name.

For the event fields, trigger rule, and validation details, read [Windows event tracing and automatic recovery](docs/windows-event-automation.md).
