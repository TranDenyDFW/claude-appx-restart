# Windows event tracing and automatic recovery

Windows records the Claude Desktop **Another program is currently using this
file** activation failure as structured events. The dialog does not need to be
screen-scraped.

## Reliable failure signal

- Channel: `Microsoft-Windows-AppModel-Runtime/Admin`
- Provider: `Microsoft-Windows-AppModel-Runtime`
- Event ID: `208`
- `ApplicationName`: `Claude_pzs8sxrjxfjjc!Claude`
- `ErrorCode`: `2147942432` (`0x80070020`)

The event predicate intentionally uses the stable application identity rather
than a versioned `PackageName`, so it remains valid after Claude updates:

```xpath
*[System[Provider[@Name='Microsoft-Windows-AppModel-Runtime'] and EventID=208]
  and EventData[
    Data[@Name='ApplicationName']='Claude_pzs8sxrjxfjjc!Claude'
    and Data[@Name='ErrorCode']='2147942432'
  ]]
```

Event ID `215` carries the more specific “error was encountered converting the
job” message and includes `PackageName` and `ContainerName`, but one failed
click emits several 215/208 records. Event 208 is the better trigger because it
contains the stable AppUserModelID. The TWinUI event 1621 is not a failure
signal: Windows can record it as a successful activation attempt while AppModel
then fails to create the process.

Other launch failures carry a different `ErrorCode` (for example `0x80073D00`)
and are deliberately not matched.

## The scheduled task

`--install-automation` registers the task from an XML definition (built by
`build_task_xml`) rather than from `schtasks` switches, because the switch
defaults leave two settings enabled that silently disable the task on a laptop
running on battery and impose a 72-hour time limit. The registered settings are
re-read and validated immediately after registration; on any mismatch the task
is deleted again.

| Setting | Value | Why |
|---|---|---|
| Trigger | `EventTrigger` with the subscription above on `Microsoft-Windows-AppModel-Runtime/Admin` | Fires on the exact failure |
| Principal | The installing user's SID, `LogonType` `InteractiveToken`, `RunLevel` `HighestAvailable` | Runs elevated, only while the user is signed in, in the user's own session |
| `MultipleInstancesPolicy` | `IgnoreNew` | A second Event 208 within seconds does not start a second repair |
| `DisallowStartIfOnBatteries` | `false` | Recovery must work on battery |
| `StopIfGoingOnBatteries` | `false` | Unplugging must not abort a repair |
| `ExecutionTimeLimit` | `PT5M` | A stuck run is terminated after five minutes |
| `Priority` | `5` | Slightly above the below-normal default so the repair is not starved |
| Action | `"<folder>\ClaudeRestart-quiet.exe" --event-triggered --yes --wait 30` (or `pythonw.exe "<folder>\claude_restart.py" ...` from source) | The windowed build runs with no console window |

`--automation-status` prints the same settings, including whether the task
starts on battery and keeps running when the machine is unplugged, together
with the last run time and result. `--install-automation` refuses to register
the task when the installed Claude application id no longer matches the
trigger identity, since such a task could never fire.

## Recovery flow

When triggered, the tool independently revalidates all of the following before
relaunching Claude:

1. A matching Event 208 exists for the currently installed package within the
   last 10 minutes.
2. `Appinfo` holds an exact `Container_Claude_<version>` Job for the same user.
3. The Job version is older than the registered Claude version.
4. Every live member is in the current user's session. A member that exited
   between the Job snapshot and this check is treated as benign, not as a
   foreign session.
5. The duplicated Job handle grants query and terminate access.

If the event matches but no exact stale Job exists, the task does **not** launch
Claude. This prevents a different `0x80070020` cause from producing a recovery
loop. After a verified repair, the utility launches Claude through
`explorer.exe shell:AppsFolder\<AUMID>` (so the packaged app never inherits the
elevated token) and requires both a visible package window and zero new
AppModel sharing-violation events.

An event-triggered run reports exit code `0` to Task Scheduler for every outcome
it handled (repaired, no action, safety stop, launch failure) and explains the
outcome in `last-run.log`; Task Scheduler would otherwise display small exit
codes as unrelated Win32 errors. Only an internal error returns `3`. An
event-triggered run never asks for UAC.

## Commands

Trace recent failures without elevation or changes:

```powershell
.\ClaudeRestart.exe --trace --minutes 180
py -3 .\claude_restart.py --trace --minutes 180
```

Install automatic recovery (one UAC prompt):

```powershell
.\ClaudeRestart.exe --install-automation
py -3 .\claude_restart.py --install-automation
```

Inspect or remove it:

```powershell
.\ClaudeRestart.exe --automation-status
.\ClaudeRestart.exe --remove-automation
```

The event-triggered recovery reacts after Windows records the failed normal
Claude click, so the error dialog can briefly appear. Using `Start Claude
Safely.cmd` remains the preflight option that checks for a stale Job before the
first activation attempt.
