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

## Recovery flow

The optional Scheduled Task uses an `OnEvent` trigger for the predicate above,
runs only in the signed-in user's interactive session, requests the highest run
level, and uses Task Scheduler's `IgnoreNew` multiple-instance policy.

When triggered, the Python utility independently revalidates all of the
following before relaunching Claude:

1. A matching Event 208 exists for the currently installed package.
2. `Appinfo` holds an exact `Container_Claude_<version>` Job for the same user.
3. The Job version is older than the registered Claude version.
4. Every live member is in the current user's session.
5. The duplicated Job handle grants query and terminate access.

If the event matches but no exact stale Job exists, the task does **not** launch
Claude. This prevents a different `0x80070020` cause from producing a recovery
loop. After a verified repair, the utility launches Claude and requires both a
visible package window and zero new AppModel sharing-violation events.

## Commands

Trace recent failures without elevation or changes:

```powershell
py -3 .\claude_restart.py --trace --minutes 180
```

Install automatic recovery (one UAC prompt):

```powershell
py -3 .\claude_restart.py --install-automation
```

Inspect or remove it:

```powershell
py -3 .\claude_restart.py --automation-status
py -3 .\claude_restart.py --remove-automation
```

The event-triggered recovery reacts after Windows records the failed normal
Claude click, so the error dialog can briefly appear. Using `Start Claude
Safely.cmd` remains the preflight option that checks for a stale Job before the
first activation attempt.
