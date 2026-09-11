# Claude Restart

`claude_restart.py` repairs the recurring Claude Desktop AppX activation failure
that reports **Another program is currently using this file**, then starts and
verifies Claude.

The utility does not kill processes by name. It finds the exact
`Container_Claude_<version>` Windows Job held by `Appinfo`, compares that version
with the currently installed Claude package, and only terminates a Job that is
unambiguously older. Its member processes are displayed before the action. A
current-version Job, a mismatched user/package identity, a newer version, or a
cross-session member causes a safety stop.

## Run it

Double-click **Start Claude Safely.cmd**. Windows will show one UAC prompt because
`Appinfo` runs as SYSTEM. The window reports `GREEN` only after a visible Claude
window appears and no new AppModel `0x80070020` events are found.

Read-only scan from PowerShell:

```powershell
py -3 .\claude_restart.py --scan
```

Historical invariant check (does not elevate or change anything):

```powershell
py -3 .\claude_restart.py --self-check
```

The most recent run is saved to `last-run.log` in this folder.

## Automatic recovery after a normal Claude click

Windows records this exact failure as structured AppModel events, so an
optional Scheduled Task can recover after a normal Claude shortcut fails—no
resident watcher is required.

Double-click **Install Automatic Recovery.cmd** once and accept the UAC prompt.
The task triggers only for Claude Event 208 with error `0x80070020`, then the
Python utility independently verifies an exact older Claude Job before it
terminates or relaunches anything. If that stale Job is absent, it stops to
avoid a retry loop.

Use **Remove Automatic Recovery.cmd** to remove the task. Read-only commands:

```powershell
py -3 .\claude_restart.py --trace --minutes 180
py -3 .\claude_restart.py --automation-status
```

See [Windows event tracing and automatic recovery](docs/windows-event-automation.md)
for the event fields, XPath predicate, safeguards, and the expected brief error
dialog behavior.

## Scope

This is a targeted repair-and-start tool, not a generic force-restart utility.
If Claude is already healthy and no older Job exists, it leaves all current
processes alone and simply opens or focuses Claude.
