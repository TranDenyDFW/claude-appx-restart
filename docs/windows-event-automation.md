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
re-read and validated immediately after registration, including that the file the
task runs is the very file just installed. An install from the release executables compares
the open handles, so a link or a replaced file cannot pass; an install from source compares
the resolved paths, because there is no installed copy to hold open.
On any mismatch the definition that was there before is put back unchanged; when
there was no task before, the one just registered is removed.

| Setting | Value | Why |
|---|---|---|
| Trigger | `EventTrigger` with the subscription above on `Microsoft-Windows-AppModel-Runtime/Admin` | Fires on the exact failure |
| Principal | The installing user's SID, `LogonType` `InteractiveToken`, `RunLevel` `HighestAvailable` | Runs elevated, only while the user is signed in, in the user's own session |
| `MultipleInstancesPolicy` | `IgnoreNew` | A second Event 208 within seconds does not start a second repair |
| `DisallowStartIfOnBatteries` | `false` | Recovery must work on battery |
| `StopIfGoingOnBatteries` | `false` | Unplugging must not abort a repair |
| `ExecutionTimeLimit` | `PT5M` | A stuck run is terminated after five minutes |
| `Priority` | `5` | Slightly above the below-normal default so the repair is not starved |
| Action | `"C:\Program Files\ClaudeRestart\versions\<version>-<id>\ClaudeRestart-quiet.exe" --event-triggered --yes --wait 30` (or `pythonw.exe "<folder>\claude_restart.py" ...` from source) | The windowed build runs with no console window, from a folder only administrators can change |

### Install location

The task runs with administrator rights, so the executables install into
`C:\Program Files\ClaudeRestart\versions\<version>-<id>` before the task is
registered. The root is resolved with `SHGetKnownFolderPath(FOLDERID_ProgramFiles)`
rather than `%ProgramFiles%`, so a non-elevated caller cannot redirect the install by
setting an environment variable before the elevation prompt.

Before anything is written, the root is proven to be administrator-only: owner SYSTEM,
Administrators or TrustedInstaller, an explicit protected permission list holding
exactly SYSTEM and Administrators full control plus Users read and execute, and no
reparse point or hard-linked file anywhere beneath it. Permissions are read and written
through open handles rather than by pathname, so a junction cannot redirect the check or
the repair. A list that merely still inherits from Program Files is repaired and then
re-verified; a folder any other account can write is refused outright, because that
account could change it between the check and the copy.

Each version installs into its own folder, which is never modified afterwards. The
payload is staged into a new folder, every staged file is hashed and re-checked through
a fresh handle, the folder is renamed into place, re-checked again, and only then does
the task point at it. Nothing is ever written over the files the live task runs, so a
failure at any point leaves the previous version and the previous task working. The
previous task definition is captured before any of this and put back if registering or
verifying the new one fails.

`--remove-automation` consults the record written during installation and deletes only
what it lists; unknown files, changed files and anything resolving outside the folder
are kept and reported, and the folder goes only when it is empty. `--force-cleanup`
also deletes files that changed since installation. Running from source installs
nothing into Program Files and warns that the task will run the interpreter and script
from their current location.

`--automation-status` prints the same settings, including whether the task starts on
battery and keeps running when the machine is unplugged, together with the last run
time and result, the exact file the task runs, whether that file sits inside the
protected folder, and whether the installed files still match what was installed.

`--install-automation` refuses to register the task when the installed Claude
application id differs from the trigger identity, since such a task could never fire,
and also when that id cannot be established at all. The id is read from the package
manifest: exactly one application selects it, several select the expected id only when
exactly one of them equals it, and anything else, including a manifest that cannot be
read, leaves the identity unknown. An unknown identity stops the tool before it
terminates anything, so it can never close the obsolete Job and then find itself unable
to start Claude again.

## Recovery flow

When triggered, the tool independently revalidates all of the following before
relaunching Claude:

1. A matching Event 208 exists for the currently installed package within the
   last 10 minutes.
2. `Appinfo` holds an exact `Container_Claude_<version>` Job for the same user.
3. The Job version is older than the registered Claude version.
4. The duplicated Job handle grants query and terminate access.
5. The Job's membership can be frozen: a handle duplicated with
   `JOB_OBJECT_SET_ATTRIBUTES` is required, and a Job that refuses one is left alone.
6. Every member is checked between two membership snapshots. Each must be in the
   current user's session and must report a start time. A member that left between the
   snapshots is benign and costs one of three attempts; a member that appeared was never
   checked, so the repair stops rather than terminating it.
7. The Job is then frozen with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` set to the number of
   validated members, so it cannot grow, and membership is read once more immediately
   before termination. Each member must still be the same process, compared by start
   time, so a reused process number cannot pass. The limit is always restored and the
   extra handle always closed, on every path.

Residual window: once the final check matches, the only remaining change is a validated
member exiting and one of the old package's own processes taking its place inside the
frozen Job. The limit prevents any growth, and the start-time comparison prevents a
reused number from passing, but Windows offers no primitive that checks membership and
terminates in one step. A run killed while the freeze is applied can leave the limit on
the obsolete Job; the next run reports that and replaces it.

`--scan` probes this on every Claude Job it can account for, current ones included, and reports
whether the freeze is available, because an obsolete Job exists only while the failure is
happening. Classification runs first, so a Job whose version is newer than the installed Claude
stops the scan with a safety stop and no freeze line is reported for any Job.

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
Claude click, so the error dialog still appears. Using `Start Claude
Safely.cmd` remains the preflight option that checks for a stale Job before the
first activation attempt.

## Closing the error dialog

The dialog from the failed click is a TaskDialog shown by `sihost.exe`, titled with the
path of the Claude executable that could not start, for example
`C:\Program Files\WindowsApps\Claude_2.110.0.0_x64__pzs8sxrjxfjjc\app\claude.exe`. It
stays open after recovery has fixed the cause, so recovery closes it, under these rules:

1. The dialogs are recorded before Claude is launched, so a dialog raised by a click after
   the launch is never among them.
2. Nothing is closed unless the launch ends GREEN: a visible Claude window and no new
   `0x80070020` event. A VISIBLE result could not check for new events, so it closes nothing.
3. Windows must have logged Event 208 with `0x80070020` for this package in the last ten
   minutes, so the dialog is tied to the failure that was fixed.
4. Each dialog must still be the same window, owned by the same process, with the same title,
   checked again before each message is sent.
5. It must be a visible, unowned `#32770` window in the session this tool runs in, owned by exactly
   `System32\sihost.exe` or `explorer.exe` in the Windows folder the shell reports.
6. Its title must be a path under the folder Claude is installed in, naming a folder of this
   package family (any version) and the application's executable from the manifest.
7. It must be a task dialog, with a `DirectUIHWND` surface and a visible, enabled button. The message
   used to press the button has the same number as a property sheet's page removal, so it is
   never sent to anything else.

The OK button is pressed with `TDM_CLICK_BUTTON`. If that does not close it, `WM_CLOSE` is
tried, which a task dialog without cancellation ignores. A dialog still open after both is
reported in the log and left for the user. The process showing the dialog is never signalled
or ended, and nothing about the dialog changes the exit code.

`--error-dialogs` lists every open dialog mentioning this package with the rule each one
fails, and closes nothing.
