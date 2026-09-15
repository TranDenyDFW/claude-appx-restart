"""The event-triggered scheduled task: its launcher, XML definition, and status."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from . import __version__, events, payload, shell, winapi
from .errors import RecoveryError
from .reporting import app_entry


AUTO_RECOVERY_TASK_NAME = payload.TASK_NAME
TASK_ARGUMENTS = payload.TASK_ARGUMENTS
TASK_XML_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
# Registered from XML rather than schtasks switches: the switch defaults leave
# DisallowStartIfOnBatteries/StopIfGoingOnBatteries enabled, which silently disables
# automatic recovery on a laptop running on battery, and impose a 72-hour time limit.
TASK_SETTINGS = (
    ("MultipleInstancesPolicy", "IgnoreNew"),
    ("DisallowStartIfOnBatteries", "false"),
    ("StopIfGoingOnBatteries", "false"),
    ("AllowHardTerminate", "true"),
    ("StartWhenAvailable", "false"),
    ("RunOnlyIfNetworkAvailable", "false"),
    ("AllowStartOnDemand", "true"),
    ("Enabled", "true"),
    ("Hidden", "false"),
    ("RunOnlyIfIdle", "false"),
    ("WakeToRun", "false"),
    ("ExecutionTimeLimit", "PT5M"),
    ("Priority", "5"),
)


def _interpreter_for_task() -> Path:
    """Return pythonw.exe (or python.exe) for the scheduled task when running from source."""
    base = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve()
    pythonw = base.with_name("pythonw.exe")
    chosen = pythonw if pythonw.is_file() else base
    reparse_tag = getattr(os.lstat(chosen), "st_reparse_tag", 0)
    if reparse_tag and reparse_tag == getattr(stat, "IO_REPARSE_TAG_APPEXECLINK", 0x8000001B):
        raise RecoveryError(
            "The Python interpreter is a Microsoft Store app-execution alias, which Task Scheduler "
            "cannot run reliably. Install Python from python.org or use ClaudeRestart.exe."
        )
    return chosen


def launcher_command(*, quiet: bool = False) -> tuple[Path, str]:
    """Return (executable, argument prefix) that re-runs this tool.

    The prefix is empty for a frozen exe and the quoted entry-script path when running
    from source. With quiet=True the windowed twin (ClaudeRestart-quiet.exe or
    pythonw.exe) is preferred so an event-triggered run shows no console window.
    """
    if winapi.is_frozen():
        executable = app_entry()
        if quiet:
            twin = executable.with_name(f"{executable.stem}{payload.QUIET_EXE_SUFFIX}{executable.suffix}")
            if twin.is_file():
                executable = twin
        return executable, ""
    interpreter = _interpreter_for_task() if quiet else Path(sys.executable).resolve()
    return interpreter, f'"{app_entry()}"'


def build_task_action(executable: Path, arguments: str) -> str:
    return f'"{executable}" {arguments}'.strip()


def task_command_path(execute: object) -> Path:
    """Resolve the Command a registered task reports to a real path.

    Task Scheduler may return the command quoted and may carry environment strings, so
    every comparison and every open of that path goes through this one function.
    """
    text = str(execute or "").strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return Path(os.path.realpath(os.path.expandvars(text)))


def task_launcher() -> tuple[Path, str]:
    """Return (executable, arguments) registered as the scheduled task action."""
    executable, prefix = launcher_command(quiet=True)
    return executable, f"{prefix} {TASK_ARGUMENTS}".strip()


def automation_task_status() -> dict[str, object]:
    task_name = shell.ps_single_quote(AUTO_RECOVERY_TASK_NAME)
    script = f"""
$task = Get-ScheduledTask -TaskName {task_name} -ErrorAction SilentlyContinue
if (-not $task) {{
    [pscustomobject]@{{ Installed = $false }} | ConvertTo-Json -Compress
    return
}}
$info = Get-ScheduledTaskInfo -TaskName {task_name} -ErrorAction SilentlyContinue
$trigger = @($task.Triggers)[0]
$action = @($task.Actions)[0]
[pscustomobject]@{{
    Installed = $true
    State = $task.State.ToString()
    MultipleInstances = $task.Settings.MultipleInstances.ToString()
    LogonType = $task.Principal.LogonType.ToString()
    RunLevel = $task.Principal.RunLevel.ToString()
    Subscription = [string]$trigger.Subscription
    Execute = [string]$action.Execute
    Arguments = [string]$action.Arguments
    DisallowStartIfOnBatteries = [bool]$task.Settings.DisallowStartIfOnBatteries
    StopIfGoingOnBatteries = [bool]$task.Settings.StopIfGoingOnBatteries
    ExecutionTimeLimit = [string]$task.Settings.ExecutionTimeLimit
    Priority = [int]$task.Settings.Priority
    Description = [string]$task.Description
    LastRunTime = if ($info) {{ $info.LastRunTime.ToString('o') }} else {{ '' }}
    LastTaskResult = if ($info) {{ $info.LastTaskResult }} else {{ $null }}
}} | ConvertTo-Json -Compress -Depth 4
"""
    raw = shell.run_powershell(script)
    return dict(json.loads(raw))


def build_task_xml(executable: Path, arguments: str, user_sid: str, working_directory: Path) -> str:
    """Return the Task Scheduler XML for the event-triggered recovery task.

    The shape mirrors what Windows itself exports for ONEVENT tasks; the settings
    come from TASK_SETTINGS so the task also runs on battery power and is limited
    to five minutes per instance.
    """
    subscription = (
        f'<QueryList><Query Id="0" Path="{events.APPMODEL_LOG}">'
        f'<Select Path="{events.APPMODEL_LOG}">{events.AUTO_RECOVERY_XPATH}</Select></Query></QueryList>'
    )
    namespace = TASK_XML_NAMESPACE
    ET.register_namespace("", namespace)

    def child(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
        node = ET.SubElement(parent, f"{{{namespace}}}{tag}", attrs)
        if text is not None:
            node.text = text
        return node

    task = ET.Element(f"{{{namespace}}}Task", {"version": "1.4"})
    info = child(task, "RegistrationInfo")
    child(info, "Author", "claude-appx-restart")
    child(
        info,
        "Description",
        f"Claude AppX Auto-Recovery {__version__}: repairs the stale Container_Claude Job "
        f"after Event 208 / {events.SHARE_VIOLATION_HEX} and starts Claude.",
    )
    child(info, "URI", f"\\{AUTO_RECOVERY_TASK_NAME}")
    trigger = child(child(task, "Triggers"), "EventTrigger")
    child(trigger, "Enabled", "true")
    child(trigger, "Subscription", subscription)  # ElementTree escapes the embedded XML.
    principal = child(child(task, "Principals"), "Principal", id="Author")
    child(principal, "UserId", user_sid)
    child(principal, "LogonType", "InteractiveToken")
    child(principal, "RunLevel", "HighestAvailable")
    settings = child(task, "Settings")
    for tag, value in TASK_SETTINGS:
        child(settings, tag, value)
    exec_node = child(child(task, "Actions", Context="Author"), "Exec")
    child(exec_node, "Command", str(executable))
    child(exec_node, "Arguments", arguments)
    child(exec_node, "WorkingDirectory", str(working_directory))
    return '<?xml version="1.0" encoding="UTF-16"?>\n' + ET.tostring(task, encoding="unicode")


def register_task_xml(xml_text: str) -> None:
    descriptor, path = tempfile.mkstemp(prefix="claude-restart-task-", suffix=".xml")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-16") as handle:
            handle.write(xml_text)
        completed = subprocess.run(
            ["schtasks.exe", "/Create", "/TN", AUTO_RECOVERY_TASK_NAME, "/XML", path, "/F"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            **shell.NO_WINDOW,
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"Could not register {AUTO_RECOVERY_TASK_NAME}: {detail}")


def delete_task() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", AUTO_RECOVERY_TASK_NAME, "/F"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        **shell.NO_WINDOW,
    )
