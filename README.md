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

## Scope

This is a targeted repair-and-start tool, not a generic force-restart utility.
If Claude is already healthy and no older Job exists, it leaves all current
processes alone and simply opens or focuses Claude.
