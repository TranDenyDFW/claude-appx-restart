#!/usr/bin/env python3
"""Safely repair Claude Desktop's stale AppX Job and start Claude.

This utility targets one verified failure mode: Appinfo retaining a versioned
Container_Claude Job from an older installed package. It never searches for or
kills processes by executable name. Instead, it duplicates the exact kernel
Job handle held by Appinfo, displays the Job's current members, terminates that
Job only when its identity and older version are unambiguous, then launches and
verifies the currently installed Claude package.

Python 3.10+; Windows only; no third-party packages. The same file is frozen by
PyInstaller into ClaudeRestart.exe (console) and ClaudeRestart-quiet.exe
(windowed twin used by the scheduled task); see build.py.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Iterable
import xml.etree.ElementTree as ET


__version__ = "1.0.0"

APP_NAME = "Claude"
EXPECTED_PACKAGE_FAMILY = "Claude_pzs8sxrjxfjjc"
APPINFO_SERVICE = "Appinfo"
APPMODEL_LOG = "Microsoft-Windows-AppModel-Runtime/Admin"
APP_ERROR_IDS = (208, 215)
SHARE_VIOLATION_HEX = "0x80070020"
SHARE_VIOLATION_DECIMAL = "2147942432"
AUTO_RECOVERY_TASK_NAME = "Claude AppX Auto-Recovery"
AUTO_RECOVERY_APPLICATION = f"{EXPECTED_PACKAGE_FAMILY}!Claude"
AUTO_RECOVERY_XPATH = (
    "*[System[Provider[@Name='Microsoft-Windows-AppModel-Runtime'] and EventID=208] "
    "and EventData[Data[@Name='ApplicationName']='Claude_pzs8sxrjxfjjc!Claude' "
    "and Data[@Name='ErrorCode']='2147942432']]"
)
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
OBJECT_NAME_INFORMATION = 1
JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x00000002
JOB_OBJECT_QUERY = 0x0004
JOB_OBJECT_TERMINATE = 0x0008
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_MORE_DATA = 234
ERROR_NOT_ALL_ASSIGNED = 1300
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SC_STATUS_PROCESS_INFO = 0
SW_SHOWNORMAL = 1
CREATE_NO_WINDOW = 0x08000000
# Every child process (PowerShell, schtasks, explorer) is spawned without a console so an
# event-triggered run under pythonw.exe / ClaudeRestart-quiet.exe never flashes a window.
_NO_WINDOW: dict[str, int] = {"creationflags": CREATE_NO_WINDOW} if os.name == "nt" else {}

IS_FROZEN = bool(getattr(sys, "frozen", False))
QUIET_EXE_SUFFIX = "-quiet"
TASK_ARGUMENTS = "--event-triggered --yes --wait 30"
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
LOG_FILE_NAME = "last-run.log"
LOG_FALLBACK_DIRNAME = "ClaudeRestart"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SAFETY_STOP = 2
EXIT_INTERNAL_ERROR = 3
EXIT_STALE_FOUND = 10


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)


class RecoveryError(RuntimeError):
    """A discovery, repair, or verification operation failed."""


class SafetyStop(RecoveryError):
    """The observed state did not satisfy the strict repair boundary."""


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class UNICODE_STRING(ctypes.Structure):
    # Buffer is a raw address: a UNICODE_STRING is length-counted and need not be
    # NUL-terminated, so it is read with wstring_at(address, Length // 2).
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    package_full_name: str
    package_family_name: str
    install_location: str
    application_id: str
    user_sid: str


@dataclass
class JobRecord:
    object_address: int
    source_handle: int
    handle: int
    granted_access: int
    name: str
    pids: list[int]
    version: str | None = None
    category: str = "unclassified"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    path: str
    command_line: str
    session_id: int | None
    creation_time: int | None


class Reporter:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def emit(self, state: str, message: str) -> None:
        line = f"[{state}] {message}"
        self.lines.append(line)
        if sys.stdout is not None:
            print(line, flush=True)

    def save(self, base: Path | None = None, fallback: Path | None = None) -> Path | None:
        """Write the run log beside the tool; fall back to %LOCALAPPDATA%\\ClaudeRestart."""
        if not self.lines:
            return None
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        text = stamp + "\n" + "\n".join(self.lines) + "\n"
        target = (base or app_location()) / LOG_FILE_NAME
        try:
            target.write_text(text, encoding="utf-8")
            return target
        except OSError:
            root = fallback or log_fallback_dir()
            root.mkdir(parents=True, exist_ok=True)
            target = root / LOG_FILE_NAME
            target.write_text(text, encoding="utf-8")
            return target


def _configure_windows_apis() -> None:
    ntdll.NtQuerySystemInformation.argtypes = [
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQuerySystemInformation.restype = wintypes.LONG
    ntdll.NtQueryObject.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryObject.restype = wintypes.LONG

    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL

    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        ctypes.POINTER(wintypes.BYTE),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    shell32.IsUserAnAdmin.restype = wintypes.BOOL
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p

    user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD


def _require_windows() -> None:
    if os.name != "nt":
        raise RecoveryError("This utility only runs on Windows.")


def _winerror(operation: str) -> RecoveryError:
    code = ctypes.get_last_error()
    return RecoveryError(f"{operation} failed: {ctypes.WinError(code)}")


def _close_handle(handle: int | None) -> None:
    if handle:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def is_admin() -> bool:
    return bool(shell32.IsUserAnAdmin())


def app_entry() -> Path:
    """Return the file a launcher must run: the exe when frozen, else this script."""
    return Path(sys.executable if IS_FROZEN else __file__).resolve()


def app_location() -> Path:
    return app_entry().parent


def log_fallback_dir() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    return (Path(root) if root else app_location()) / LOG_FALLBACK_DIRNAME


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

    The prefix is empty for a frozen exe and the quoted script path when running from
    source. With quiet=True the windowed twin (ClaudeRestart-quiet.exe or pythonw.exe)
    is preferred so an event-triggered run shows no console window.
    """
    if IS_FROZEN:
        executable = app_entry()
        if quiet:
            twin = executable.with_name(f"{executable.stem}{QUIET_EXE_SUFFIX}{executable.suffix}")
            if twin.is_file():
                executable = twin
        return executable, ""
    interpreter = _interpreter_for_task() if quiet else Path(sys.executable).resolve()
    return interpreter, f'"{app_entry()}"'


def build_task_action(executable: Path, arguments: str) -> str:
    return f'"{executable}" {arguments}'.strip()


def task_launcher() -> tuple[Path, str]:
    """Return (executable, arguments) registered as the scheduled task action."""
    executable, prefix = launcher_command(quiet=True)
    return executable, f"{prefix} {TASK_ARGUMENTS}".strip()


def elevation_request(argv: list[str]) -> tuple[str, str, str]:
    """Return (target, parameters, working directory) for the ShellExecute runas relaunch."""
    forwarded = [arg for arg in argv if arg != "--elevated"]
    executable, prefix = launcher_command()
    parts = ([prefix.strip('"')] if prefix else []) + forwarded + ["--elevated"]
    return str(executable), subprocess.list2cmdline(parts), str(app_location())


def relaunch_elevated() -> None:
    target, parameters, workdir = elevation_request(sys.argv[1:])
    if IS_FROZEN:
        # The elevated child outlives this process; PyInstaller (>= 6.9) must give it its
        # own extraction directory instead of the one deleted when this parent exits.
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    result = shell32.ShellExecuteW(None, "runas", target, parameters, workdir, SW_SHOWNORMAL)
    value = int(result or 0)
    if value <= 32:
        raise RecoveryError(f"Administrator elevation was not started (ShellExecute code {value}).")


def enable_debug_privilege() -> None:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token)
    ):
        raise _winerror("OpenProcessToken")
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            raise _winerror("LookupPrivilegeValueW")
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(privileges), 0, None, None
        ):
            raise _winerror("AdjustTokenPrivileges")
        if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
            raise RecoveryError("The elevated token does not contain SeDebugPrivilege.")
    finally:
        _close_handle(int(token.value or 0))


def _run_powershell(script: str, timeout: int = 30) -> str:
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
        **_NO_WINDOW,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"PowerShell query failed ({completed.returncode}): {detail}")
    return completed.stdout.strip()


def get_claude_package() -> PackageInfo:
    script = r"""
$result = @(
    Get-AppxPackage -Name 'Claude' -ErrorAction Stop |
    Sort-Object Version -Descending |
    ForEach-Object {
        $applicationId = 'Claude'
        try {
            $manifest = Get-AppxPackageManifest -Package $_.PackageFullName -ErrorAction Stop
            $manifestId = [string](@($manifest.Package.Applications.Application)[0].Id)
            if ($manifestId) { $applicationId = $manifestId }
        } catch {}
        [pscustomobject]@{
            Name = $_.Name
            Version = $_.Version.ToString()
            PackageFullName = $_.PackageFullName
            PackageFamilyName = $_.PackageFamilyName
            InstallLocation = $_.InstallLocation
            ApplicationId = $applicationId
            UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        }
    }
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = _run_powershell(script)
    if not raw:
        raise RecoveryError("Claude is not registered for the current Windows user.")
    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]
    if len(data) != 1:
        versions = ", ".join(str(item.get("Version")) for item in data) or "none"
        raise SafetyStop(f"Expected one registered Claude package; observed: {versions}.")
    item = data[0]
    package = PackageInfo(
        name=str(item["Name"]),
        version=str(item["Version"]),
        package_full_name=str(item["PackageFullName"]),
        package_family_name=str(item["PackageFamilyName"]),
        install_location=str(item["InstallLocation"]),
        application_id=str(item["ApplicationId"]),
        user_sid=str(item["UserSid"]),
    )
    if package.name != APP_NAME or package.package_family_name != EXPECTED_PACKAGE_FAMILY:
        raise SafetyStop(
            "The registered package identity is not the reviewed Claude package: "
            f"{package.package_family_name}."
        )
    version_key(package.version)
    expected_start = f"{package.name}_{package.version}"
    if not package.package_full_name.startswith(expected_start):
        raise SafetyStop(f"Unexpected package full name: {package.package_full_name}.")
    return package


def get_appinfo_pid() -> int:
    manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not manager:
        raise _winerror("OpenSCManagerW")
    service = None
    try:
        service = advapi32.OpenServiceW(manager, APPINFO_SERVICE, SERVICE_QUERY_STATUS)
        if not service:
            raise _winerror("OpenServiceW(Appinfo)")
        status = SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        ok = advapi32.QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            ctypes.cast(ctypes.byref(status), ctypes.POINTER(wintypes.BYTE)),
            ctypes.sizeof(status),
            ctypes.byref(needed),
        )
        if not ok:
            raise _winerror("QueryServiceStatusEx(Appinfo)")
        return int(status.dwProcessId)
    finally:
        if service:
            _close_handle(int(service))
        _close_handle(int(manager))


def _system_handles() -> list[SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]:
    size = 1 << 20
    while size <= (1 << 29):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = int(
            ntdll.NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            )
        )
        unsigned = status & 0xFFFFFFFF
        if status >= 0:
            count = ctypes.c_size_t.from_buffer(buffer, 0).value
            offset = ctypes.sizeof(ctypes.c_size_t) * 2
            entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            required = offset + count * entry_size
            if required > size:
                raise RecoveryError("NtQuerySystemInformation returned an invalid handle count.")
            return [
                SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer_copy(buffer, offset + index * entry_size)
                for index in range(count)
            ]
        if unsigned in (0xC0000004, 0xC0000023, 0x80000005):
            size = max(size * 2, int(needed.value) + 65536)
            continue
        raise RecoveryError(f"NtQuerySystemInformation failed with NTSTATUS 0x{unsigned:08X}.")
    raise RecoveryError("System handle table exceeded the 512 MiB safety ceiling.")


def _job_object_type_index() -> int:
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise _winerror("CreateJobObjectW")
    handle_value = int(handle)
    try:
        for entry in _system_handles():
            if int(entry.UniqueProcessId) == os.getpid() and int(entry.HandleValue) == handle_value:
                return int(entry.ObjectTypeIndex)
    finally:
        _close_handle(handle_value)
    raise RecoveryError("Could not identify the Windows Job object type index.")


def _query_object_name(handle: int) -> str | None:
    size = 4096
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = int(
            ntdll.NtQueryObject(
                wintypes.HANDLE(handle),
                OBJECT_NAME_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            )
        )
        if status >= 0:
            value = UNICODE_STRING.from_buffer_copy(buffer)
            if not value.Buffer or not value.Length:
                return None
            # The address points into `buffer`, which stays alive for this read.
            return ctypes.wstring_at(int(value.Buffer), value.Length // ctypes.sizeof(ctypes.c_wchar))
        unsigned = status & 0xFFFFFFFF
        if unsigned in (0xC0000004, 0xC0000023, 0x80000005):
            size = max(size * 2, int(needed.value) + 2)
            continue
        return None
    return None


def query_job_pids(handle: int) -> list[int]:
    capacity = 128
    for _ in range(6):
        size = 8 + capacity * ctypes.sizeof(ctypes.c_size_t)
        buffer = ctypes.create_string_buffer(size)
        returned = wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = kernel32.QueryInformationJobObject(
            wintypes.HANDLE(handle),
            JOB_OBJECT_BASIC_PROCESS_ID_LIST,
            buffer,
            size,
            ctypes.byref(returned),
        )
        if ok:
            in_list = wintypes.DWORD.from_buffer(buffer, 4).value
            if in_list > capacity:
                capacity = int(in_list) + 32
                continue
            array_type = ctypes.c_size_t * in_list
            values = array_type.from_buffer_copy(buffer, 8) if in_list else ()
            return sorted({int(value) for value in values if value})
        if ctypes.get_last_error() == ERROR_MORE_DATA:
            capacity *= 4
            continue
        raise _winerror("QueryInformationJobObject")
    raise RecoveryError("Claude Job contained more process IDs than the safety ceiling permits.")


def discover_claude_jobs(appinfo_pid: int) -> list[JobRecord]:
    if not appinfo_pid:
        return []
    job_type = _job_object_type_index()
    handles = _system_handles()
    candidates: dict[int, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX] = {}
    for entry in handles:
        if int(entry.UniqueProcessId) != appinfo_pid or int(entry.ObjectTypeIndex) != job_type:
            continue
        object_address = int(entry.Object or 0)
        old = candidates.get(object_address)
        score = int(bool(entry.GrantedAccess & JOB_OBJECT_QUERY)) + int(
            bool(entry.GrantedAccess & JOB_OBJECT_TERMINATE)
        )
        old_score = -1 if old is None else int(bool(old.GrantedAccess & JOB_OBJECT_QUERY)) + int(
            bool(old.GrantedAccess & JOB_OBJECT_TERMINATE)
        )
        if old is None or score > old_score:
            candidates[object_address] = entry

    owner = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, appinfo_pid)
    if not owner:
        raise _winerror(f"OpenProcess(Appinfo PID {appinfo_pid})")
    records: list[JobRecord] = []
    try:
        for object_address, entry in candidates.items():
            duplicate = wintypes.HANDLE()
            if not kernel32.DuplicateHandle(
                owner,
                wintypes.HANDLE(int(entry.HandleValue)),
                kernel32.GetCurrentProcess(),
                ctypes.byref(duplicate),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            ):
                continue
            duplicate_value = int(duplicate.value or 0)
            name = _query_object_name(duplicate_value)
            if not name or "Container_Claude_" not in name:
                _close_handle(duplicate_value)
                continue
            try:
                pids = query_job_pids(duplicate_value)
            except Exception:
                _close_handle(duplicate_value)
                raise
            records.append(
                JobRecord(
                    object_address=object_address,
                    source_handle=int(entry.HandleValue),
                    handle=duplicate_value,
                    granted_access=int(entry.GrantedAccess),
                    name=name,
                    pids=pids,
                )
            )
    finally:
        _close_handle(int(owner))
    return sorted(records, key=lambda record: record.name)


def version_key(value: str) -> tuple[int, int, int, int]:
    pieces = value.split(".")
    if len(pieces) != 4 or any(not piece.isdigit() for piece in pieces):
        raise SafetyStop(f"Expected a four-part numeric version; observed {value!r}.")
    return tuple(int(piece) for piece in pieces)  # type: ignore[return-value]


def classify_jobs(package: PackageInfo, jobs: Iterable[JobRecord]) -> tuple[list[JobRecord], list[JobRecord]]:
    stem = f"{package.name}_{package.version}"
    if not package.package_full_name.startswith(stem):
        raise SafetyStop(f"Unexpected package identity: {package.package_full_name}.")
    suffix = package.package_full_name[len(stem) :]
    pattern = re.compile(
        r"^\\Container_"
        + re.escape(package.name)
        + r"_(?P<version>\d+\.\d+\.\d+\.\d+)"
        + re.escape(suffix)
        + "-"
        + re.escape(package.user_sid)
        + r"$"
    )
    current_key = version_key(package.version)
    stale: list[JobRecord] = []
    current: list[JobRecord] = []
    unexpected: list[str] = []
    for job in jobs:
        match = pattern.fullmatch(job.name)
        if not match:
            unexpected.append(job.name)
            continue
        job.version = match.group("version")
        observed_key = version_key(job.version)
        if observed_key < current_key:
            job.category = "stale"
            stale.append(job)
        elif observed_key == current_key:
            job.category = "current"
            current.append(job)
        else:
            unexpected.append(job.name)
    if unexpected:
        rendered = "\n  ".join(unexpected)
        raise SafetyStop(
            "Claude-like Job identity did not fit the reviewed older/current rule:\n  " + rendered
        )
    return stale, current


def _process_session_id(pid: int) -> int | None:
    session = wintypes.DWORD()
    ctypes.set_last_error(0)
    if not kernel32.ProcessIdToSessionId(pid, ctypes.byref(session)):
        return None
    return int(session.value)


def _native_process_info(pid: int) -> ProcessInfo:
    session = _process_session_id(pid)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ProcessInfo(pid, "<exited or inaccessible>", "", "", session, None)
    try:
        path_buffer = ctypes.create_unicode_buffer(32768)
        path_size = wintypes.DWORD(len(path_buffer))
        path = ""
        if kernel32.QueryFullProcessImageNameW(handle, 0, path_buffer, ctypes.byref(path_size)):
            path = path_buffer.value
        created = FILETIME()
        exited = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        creation_time = None
        if kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            creation_time = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        return ProcessInfo(pid, Path(path).name if path else "<unknown>", path, "", session, creation_time)
    finally:
        _close_handle(int(handle))


def _command_lines(pids: Iterable[int]) -> dict[int, str]:
    values = sorted({int(pid) for pid in pids if pid > 0})
    if not values:
        return {}
    filters = " OR ".join(f"ProcessId = {pid}" for pid in values)
    escaped = filters.replace("'", "''")
    script = f"""
$result = @(Get-CimInstance Win32_Process -Filter '{escaped}' -ErrorAction SilentlyContinue |
    Select-Object ProcessId,CommandLine)
ConvertTo-Json -InputObject @($result) -Compress -Depth 3
"""
    try:
        raw = _run_powershell(script, timeout=20)
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        return {int(item["ProcessId"]): str(item.get("CommandLine") or "") for item in data}
    except Exception:
        return {}


def process_details(pids: Iterable[int]) -> list[ProcessInfo]:
    native = [_native_process_info(pid) for pid in sorted(set(pids))]
    commands = _command_lines(info.pid for info in native)
    return [
        ProcessInfo(
            info.pid,
            info.name,
            info.path,
            commands.get(info.pid, ""),
            info.session_id,
            info.creation_time,
        )
        for info in native
    ]


def _partition_members(
    details: Iterable[ProcessInfo], current_session: int | None
) -> tuple[list[int], list[int]]:
    """Split Job members into (exited, foreign-session) PIDs.

    A member that exited between the Job snapshot and this check has no session and no
    process handle; that is benign, not a sign of another user's session.
    """
    exited: list[int] = []
    foreign: list[int] = []
    for info in details:
        if info.session_id is None and info.name == "<exited or inaccessible>":
            exited.append(info.pid)
        elif current_session is None or info.session_id is None or info.session_id != current_session:
            foreign.append(info.pid)
    return exited, foreign


def validate_live_members(
    job: JobRecord, appinfo_pid: int, reporter: Reporter | None = None
) -> list[ProcessInfo]:
    live_pids = query_job_pids(job.handle)
    prohibited = {0, 4, os.getpid(), appinfo_pid}
    collision = prohibited.intersection(live_pids)
    if collision:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: protected/current PID(s) present: {sorted(collision)}."
        )
    current_session = _process_session_id(os.getpid())
    details = process_details(live_pids)
    exited, foreign = _partition_members(details, current_session)
    if foreign:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: PID(s) are not verified in this user session: "
            f"{foreign}."
        )
    if exited and reporter is not None:
        reporter.emit("NOTE", f"{len(exited)} member(s) of {job.name} exited before validation: {exited}.")
    job.pids = [pid for pid in live_pids if pid not in exited]
    return details


def terminate_exact_job(job: JobRecord) -> None:
    required = JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE
    if job.granted_access & required != required:
        raise SafetyStop(
            f"Appinfo Job handle 0x{job.source_handle:X} lacks reviewed query/terminate access "
            f"(granted 0x{job.granted_access:X})."
        )
    ctypes.set_last_error(0)
    if not kernel32.TerminateJobObject(wintypes.HANDLE(job.handle), 0xC0DE):
        raise _winerror(f"TerminateJobObject({job.name})")
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if not query_job_pids(job.handle):
            return
        time.sleep(0.2)
    survivors = query_job_pids(job.handle)
    raise RecoveryError(f"The stale Job still reports member PID(s) after termination: {survivors}.")


def close_job_records(jobs: Iterable[JobRecord]) -> None:
    for job in jobs:
        _close_handle(job.handle)
        job.handle = 0


def _window_process_path(pid: int) -> str:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        _close_handle(int(handle))


def visible_claude_windows(package: PackageInfo) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    expected_root = os.path.normcase(os.path.normpath(package.install_location)) + os.sep
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @callback_type
    def visit(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        title_buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title_buffer, length + 1)
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        path = _window_process_path(int(pid.value))
        normalized = os.path.normcase(os.path.normpath(path)) if path else ""
        if normalized.startswith(expected_root):
            found.append(
                {"hwnd": int(hwnd), "pid": int(pid.value), "title": title_buffer.value, "path": path}
            )
        return True

    if not user32.EnumWindows(visit, 0):
        raise _winerror("EnumWindows")
    return found


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _event_parts(xml_text: str) -> tuple[str, int | None, int | None, dict[str, str]]:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    provider = root.find("./e:System/e:Provider", namespace)
    event_id = root.findtext("./e:System/e:EventID", default="", namespaces=namespace)
    record_id = root.findtext("./e:System/e:EventRecordID", default="", namespaces=namespace)
    data = {
        str(node.attrib.get("Name", "")): str(node.text or "")
        for node in root.findall("./e:EventData/e:Data", namespace)
    }
    return (
        "" if provider is None else str(provider.attrib.get("Name", "")),
        int(event_id) if event_id.isdigit() else None,
        int(record_id) if record_id.isdigit() else None,
        data,
    )


def is_auto_recovery_event(xml_text: str) -> bool:
    """Return True only for the structured Claude 0x80070020 launch failure."""
    try:
        provider, event_id, _record_id, data = _event_parts(xml_text)
    except (ET.ParseError, ValueError):
        return False
    return (
        provider == "Microsoft-Windows-AppModel-Runtime"
        and event_id == 208
        and data.get("ApplicationName") == AUTO_RECOVERY_APPLICATION
        and data.get("ErrorCode") == SHARE_VIOLATION_DECIMAL
    )


def auto_recovery_events(
    package: PackageInfo | None = None,
    *,
    minutes: int = 180,
) -> list[dict[str, object]]:
    if minutes < 1 or minutes > 10080:
        raise RecoveryError("Trace window must be between 1 minute and 7 days.")
    xpath = _ps_single_quote(AUTO_RECOVERY_XPATH)
    log_name = _ps_single_quote(APPMODEL_LOG)
    script = f"""
$cutoff = (Get-Date).AddMinutes(-{minutes})
$result = @(
    Get-WinEvent -LogName {log_name} -FilterXPath {xpath} -ErrorAction SilentlyContinue |
    Where-Object TimeCreated -ge $cutoff |
    ForEach-Object {{
        [pscustomobject]@{{
            RecordId = [long]$_.RecordId
            TimeCreated = $_.TimeCreated.ToString('o')
            Xml = $_.ToXml()
        }}
    }}
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = _run_powershell(script, timeout=30)
    rows = json.loads(raw) if raw else []
    if isinstance(rows, dict):
        rows = [rows]
    events: list[dict[str, object]] = []
    for row in rows:
        xml_text = str(row.get("Xml") or "")
        if not is_auto_recovery_event(xml_text):
            continue
        _provider, _event_id, record_id, data = _event_parts(xml_text)
        if package is not None and data.get("PackageName") != package.package_full_name:
            continue
        events.append(
            {
                "record_id": record_id,
                "time_created": str(row.get("TimeCreated") or ""),
                "package_name": data.get("PackageName", ""),
                "application_name": data.get("ApplicationName", ""),
                "error_code": data.get("ErrorCode", ""),
            }
        )
    return events


def trace_auto_recovery_events(reporter: Reporter, minutes: int) -> int:
    package = get_claude_package()
    events = auto_recovery_events(package, minutes=minutes)
    if not events:
        reporter.emit(
            "TRACE CLEAR",
            f"No structured Claude {SHARE_VIOLATION_HEX} launch failures in the last {minutes} minute(s).",
        )
        return 0
    reporter.emit(
        "TRACE RED",
        f"Windows recorded {len(events)} structured Claude {SHARE_VIOLATION_HEX} launch failure(s) "
        f"in the last {minutes} minute(s).",
    )
    for event in events[:20]:
        reporter.emit(
            "EVENT",
            f"Record {event['record_id']} at {event['time_created']}: Event 208, "
            f"{event['application_name']}, error {event['error_code']}.",
        )
    return 10


def automation_task_status() -> dict[str, object]:
    task_name = _ps_single_quote(AUTO_RECOVERY_TASK_NAME)
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
    raw = _run_powershell(script)
    return dict(json.loads(raw))


def build_task_xml(executable: Path, arguments: str, user_sid: str, working_directory: Path) -> str:
    """Return the Task Scheduler XML for the event-triggered recovery task.

    The shape mirrors what Windows itself exports for ONEVENT tasks; the settings
    come from TASK_SETTINGS so the task also runs on battery power and is limited
    to five minutes per instance.
    """
    subscription = (
        f'<QueryList><Query Id="0" Path="{APPMODEL_LOG}">'
        f'<Select Path="{APPMODEL_LOG}">{AUTO_RECOVERY_XPATH}</Select></Query></QueryList>'
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
        f"after Event 208 / {SHARE_VIOLATION_HEX} and starts Claude.",
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


def _register_task_xml(xml_text: str) -> None:
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
            **_NO_WINDOW,
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"Could not register {AUTO_RECOVERY_TASK_NAME}: {detail}")


def _delete_task() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", AUTO_RECOVERY_TASK_NAME, "/F"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        **_NO_WINDOW,
    )


def install_auto_recovery(reporter: Reporter) -> None:
    package = get_claude_package()
    executable, arguments = task_launcher()
    if IS_FROZEN and QUIET_EXE_SUFFIX not in executable.name:
        reporter.emit(
            "WARN",
            f"{executable.stem}{QUIET_EXE_SUFFIX}{executable.suffix} was not found beside "
            f"{executable.name}; automatic recovery will show a console window. "
            "Extract the full release ZIP to avoid this.",
        )
    _register_task_xml(build_task_xml(executable, arguments, package.user_sid, app_location()))

    status = automation_task_status()
    valid = (
        status.get("Installed") is True
        and status.get("MultipleInstances") == "IgnoreNew"
        and status.get("LogonType") in ("Interactive", "InteractiveToken")
        and status.get("RunLevel") in ("Highest", "HighestAvailable")
        and status.get("DisallowStartIfOnBatteries") is False
        and status.get("StopIfGoingOnBatteries") is False
        and bool(status.get("Subscription"))
        and AUTO_RECOVERY_APPLICATION in str(status.get("Subscription"))
        and SHARE_VIOLATION_DECIMAL in str(status.get("Subscription"))
        and os.path.normcase(str(status.get("Execute")).strip('"')) == os.path.normcase(str(executable))
        and str(status.get("Arguments")) == arguments
    )
    if not valid:
        _delete_task()
        raise SafetyStop("The registered task did not preserve the reviewed trigger/action settings; it was removed.")
    reporter.emit(
        "INSTALLED",
        f"Task '{AUTO_RECOVERY_TASK_NAME}' watches Event 208 for {AUTO_RECOVERY_APPLICATION} / "
        f"{SHARE_VIOLATION_HEX}, runs only while this user is signed in, and also runs on battery power.",
    )
    reporter.emit("ACTION", build_task_action(executable, arguments))
    reporter.emit("PACKAGE", f"Current package verified: {package.package_full_name}")


def remove_auto_recovery(reporter: Reporter) -> None:
    status = automation_task_status()
    if not status.get("Installed"):
        reporter.emit("NOT INSTALLED", f"Task '{AUTO_RECOVERY_TASK_NAME}' is already absent.")
        return
    completed = _delete_task()
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"Could not remove {AUTO_RECOVERY_TASK_NAME}: {detail}")
    reporter.emit("REMOVED", f"Task '{AUTO_RECOVERY_TASK_NAME}' was removed.")


def show_auto_recovery_status(reporter: Reporter) -> int:
    status = automation_task_status()
    if not status.get("Installed"):
        reporter.emit("NOT INSTALLED", f"Task '{AUTO_RECOVERY_TASK_NAME}' is absent.")
        return 1
    reporter.emit(
        "AUTOMATION",
        f"State={status.get('State')}; run level={status.get('RunLevel')}; "
        f"logon={status.get('LogonType')}; instances={status.get('MultipleInstances')}.",
    )
    reporter.emit("ACTION", f"{status.get('Execute')} {status.get('Arguments')}")
    on_battery = "yes" if status.get("DisallowStartIfOnBatteries") is False else "no"
    reporter.emit(
        "SETTINGS",
        f"starts on battery={on_battery}; time limit={status.get('ExecutionTimeLimit') or 'default'}; "
        f"priority={status.get('Priority')}.",
    )
    if status.get("Description"):
        reporter.emit("DESCRIPTION", str(status.get("Description")))
    reporter.emit(
        "LAST RUN",
        f"{status.get('LastRunTime') or 'never'}; result={status.get('LastTaskResult')}",
    )
    return EXIT_OK


def appmodel_share_violations(package: PackageInfo, since: datetime) -> list[dict[str, object]]:
    start = _ps_single_quote(since.isoformat())
    package_name = _ps_single_quote(package.package_full_name)
    log_name = _ps_single_quote(APPMODEL_LOG)
    event_ids = ",".join(str(event_id) for event_id in APP_ERROR_IDS)
    script = f"""
$start = [DateTimeOffset]::Parse({start}).LocalDateTime
$package = {package_name}
$result = @(
    Get-WinEvent -FilterHashtable @{{LogName={log_name}; Id={event_ids}; StartTime=$start}} -ErrorAction SilentlyContinue |
    ForEach-Object {{
        $text = $_.ToXml() + "`n" + $_.Message
        if ($text.Contains($package) -and (
            $text.Contains('0x80070020') -or
            $text.Contains('2147942432') -or
            $text.Contains('-2147024864')
        )) {{
            [pscustomobject]@{{
                Id = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Message = $_.Message
            }}
        }}
    }}
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = _run_powershell(script, timeout=30)
    data = json.loads(raw) if raw else []
    if isinstance(data, dict):
        data = [data]
    return list(data)


def launch_and_verify(package: PackageInfo, reporter: Reporter, wait_seconds: int) -> bool:
    aumid = f"{package.package_family_name}!{package.application_id}"
    started_at = datetime.now(timezone.utc)
    reporter.emit("LAUNCH", f"Starting shell:AppsFolder\\{aumid}")
    # Explorer hands the activation to the running (unelevated) shell and exits, so the
    # packaged app never inherits this process's elevated token.
    explorer = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe"
    process = subprocess.Popen(
        [str(explorer), f"shell:AppsFolder\\{aumid}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **_NO_WINDOW,
    )
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    deadline = time.monotonic() + wait_seconds
    windows: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        windows = visible_claude_windows(package)
        if windows:
            break
        time.sleep(0.5)
    time.sleep(0.75)
    try:
        violations = appmodel_share_violations(package, started_at)
        event_check = "complete"
    except Exception as exc:
        violations = []
        event_check = f"unavailable: {exc}"

    if violations:
        ids = ", ".join(str(event.get("Id")) for event in violations)
        reporter.emit(
            "RED",
            f"Claude logged {len(violations)} new {SHARE_VIOLATION_HEX} AppModel event(s); IDs: {ids}.",
        )
        return False
    if not windows:
        reporter.emit(
            "RED",
            f"No visible Claude window appeared within {wait_seconds} seconds (event check {event_check}).",
        )
        return False
    window = windows[0]
    if event_check == "complete":
        reporter.emit(
            "GREEN",
            f"Visible Claude window verified at PID {window['pid']}; zero new {SHARE_VIOLATION_HEX} events.",
        )
    else:
        reporter.emit(
            "VISIBLE",
            f"Claude window is visible at PID {window['pid']}; AppModel event check {event_check}.",
        )
    return True


def historical_self_check(reporter: Reporter) -> bool:
    fixtures = [
        ("1.34493.1.0", "1.34493.0.0", 8),
        ("1.37937.0.0", "1.34493.1.0", 7),
        ("1.37937.3.0", "1.37937.0.0", 7),
        ("1.44121.2.0", "1.40609.0.0", 16),
        ("1.44121.4.0", "1.44121.2.0", 10),
        ("1.46388.1.0", "1.44121.4.0", 7),
        ("1.46388.2.0", "1.46388.1.0", 7),
        ("1.52386.0.0", "1.49585.0.0", 4),
    ]
    # Synthetic SID: the production path discovers the signed-in user's SID.
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    passed = 0
    for current_version, older_version, members in fixtures:
        suffix = "_x64__pzs8sxrjxfjjc"
        package = PackageInfo(
            name="Claude",
            version=current_version,
            package_full_name=f"Claude_{current_version}{suffix}",
            package_family_name=EXPECTED_PACKAGE_FAMILY,
            install_location=r"C:\Program Files\WindowsApps\fixture",
            application_id="Claude",
            user_sid=sid,
        )
        current_job = JobRecord(
            1,
            1,
            0,
            JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE,
            rf"\Container_Claude_{current_version}{suffix}-{sid}",
            list(range(100, 100 + members)),
        )
        older_job = JobRecord(
            2,
            2,
            0,
            JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE,
            rf"\Container_Claude_{older_version}{suffix}-{sid}",
            list(range(200, 200 + members)),
        )
        stale, current = classify_jobs(package, [current_job, older_job])
        passed += int(stale == [older_job] and current == [current_job])

    safety_checks = 0
    base_version = "1.52386.0.0"
    suffix = "_x64__pzs8sxrjxfjjc"
    package = PackageInfo(
        "Claude",
        base_version,
        f"Claude_{base_version}{suffix}",
        EXPECTED_PACKAGE_FAMILY,
        r"C:\Program Files\WindowsApps\fixture",
        "Claude",
        sid,
    )
    current_only = JobRecord(
        3,
        3,
        0,
        JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE,
        rf"\Container_Claude_{base_version}{suffix}-{sid}",
        [],
    )
    stale, current = classify_jobs(package, [current_only])
    safety_checks += int(not stale and current == [current_only])
    for unsafe_name in (
        rf"\Container_Claude_1.60000.0.0{suffix}-{sid}",
        rf"\Container_Claude_1.49585.0.0{suffix}-S-1-5-21-1-2-3-1001",
    ):
        unsafe_job = JobRecord(4, 4, 0, 0, unsafe_name, [])
        try:
            classify_jobs(package, [unsafe_job])
        except SafetyStop:
            safety_checks += 1

    reporter.emit(
        "SELF-CHECK",
        f"Production classifier selected only the older Job in {passed}/{len(fixtures)} incidents; "
        f"all {safety_checks}/3 current/newer/wrong-user guards passed; member counts ranged from "
        f"{min(item[2] for item in fixtures)} to {max(item[2] for item in fixtures)}.",
    )
    return passed == len(fixtures) and safety_checks == 3


def run(args: argparse.Namespace, reporter: Reporter) -> int:
    package = get_claude_package()
    reporter.emit("PACKAGE", f"Installed: {package.package_full_name}")
    installed_aumid = f"{package.package_family_name}!{package.application_id}"
    if installed_aumid != AUTO_RECOVERY_APPLICATION:
        reporter.emit(
            "WARN",
            f"Installed application id {installed_aumid} differs from the trigger identity "
            f"{AUTO_RECOVERY_APPLICATION}; automatic recovery will not fire until the tool is updated.",
        )
    if args.event_triggered:
        events = auto_recovery_events(package, minutes=10)
        if not events:
            reporter.emit(
                "NO ACTION",
                "Scheduled invocation had no matching current-package Event 208 in the last 10 minutes.",
            )
            return 0
        newest = events[0]
        reporter.emit(
            "TRIGGER",
            f"Validated Windows Event record {newest['record_id']} at {newest['time_created']}.",
        )
    appinfo_pid = get_appinfo_pid()
    if not appinfo_pid:
        reporter.emit("SCAN", "Appinfo is stopped, so it cannot currently retain a stale Claude Job.")
        if args.scan:
            return 0
        if args.event_triggered:
            reporter.emit(
                "NO ACTION",
                "The event matched, but Appinfo is stopped; automatic relaunch was suppressed.",
            )
            return 0
        return 0 if launch_and_verify(package, reporter, args.wait) else 1

    reporter.emit("SCAN", f"Inspecting Windows Job handles held by Appinfo PID {appinfo_pid}.")
    jobs = discover_claude_jobs(appinfo_pid)
    try:
        stale, current = classify_jobs(package, jobs)
        for job in current:
            reporter.emit(
                "CURRENT",
                f"Leaving current-version Job untouched: {job.name} ({len(job.pids)} member(s)).",
            )
        for job in stale:
            reporter.emit(
                "STALE",
                f"Verified older Job: {job.name} ({len(job.pids)} member(s)).",
            )
            for info in process_details(job.pids):
                command = " ".join(info.command_line.split())
                detail = command or info.path or info.name
                reporter.emit("MEMBER", f"PID {info.pid}: {detail}")

        if not stale:
            reporter.emit("SAFE", "No exact older Claude AppX Job is present.")
        if args.scan:
            reporter.emit("DRY-RUN", "No processes were terminated and Claude was not launched.")
            return EXIT_STALE_FOUND if stale else EXIT_OK
        if args.event_triggered and not stale:
            reporter.emit(
                "NO ACTION",
                "The event matched, but no exact older Claude Job exists; automatic relaunch was suppressed.",
            )
            return EXIT_OK
        if stale and not args.yes:
            if not _stdin_is_interactive():
                raise SafetyStop("Confirmation is required; rerun interactively or pass --yes.")
            answer = input("Type REPAIR to terminate only the verified stale Job member(s): ").strip()
            if answer != "REPAIR":
                reporter.emit("CANCELLED", "No processes were terminated.")
                return EXIT_SAFETY_STOP

        for job in stale:
            validate_live_members(job, appinfo_pid, reporter)
            reporter.emit(
                "REVALIDATED",
                f"{job.name} has {len(job.pids)} live member(s), all in this user session.",
            )
            terminate_exact_job(job)
            reporter.emit("CLOSED", f"Terminated the exact stale Job and its {len(job.pids)} member(s).")
    finally:
        close_job_records(jobs)

    if stale:
        time.sleep(0.5)
    return EXIT_OK if launch_and_verify(package, reporter, args.wait) else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repair the verified stale Claude AppX Job failure and start Claude Desktop."
    )
    parser.add_argument("--version", action="version", version=f"ClaudeRestart {__version__}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--scan",
        action="store_true",
        help="read-only scan; exit 10 when an exact stale Job is found",
    )
    mode.add_argument(
        "--trace",
        action="store_true",
        help="read the structured Windows events for this exact launch failure",
    )
    mode.add_argument(
        "--install-automation",
        action="store_true",
        help="install the event-triggered automatic recovery task",
    )
    mode.add_argument(
        "--remove-automation",
        action="store_true",
        help="remove the event-triggered automatic recovery task",
    )
    mode.add_argument(
        "--automation-status",
        action="store_true",
        help="show the automatic recovery task status",
    )
    mode.add_argument(
        "--self-check",
        action="store_true",
        help="validate the historical version-selection invariant without elevation",
    )
    mode.add_argument("--event-triggered", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--yes", action="store_true", help="skip the typed REPAIR confirmation")
    parser.add_argument(
        "--wait",
        type=int,
        default=20,
        metavar="SECONDS",
        help="seconds to wait for a visible Claude window (default: 20)",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        default=180,
        metavar="MINUTES",
        help="lookback window for --trace (default: 180)",
    )
    parser.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-elevate", action="store_true", help=argparse.SUPPRESS)
    return parser


def _stdin_is_interactive() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _pause() -> None:
    if sys.stdin is None or sys.stdout is None:
        return
    try:
        input("Press Enter to close...")
    except (EOFError, RuntimeError, OSError, ValueError):
        pass


def event_triggered_exit_code(exit_code: int) -> int:
    """Map handled outcomes to 0 for Task Scheduler.

    Task Scheduler renders small exit codes as Win32 errors (2 reads as "file not
    found"), so an event-triggered run reports 0 for every outcome it handled and
    explained in last-run.log; only an internal error stays non-zero.
    """
    return EXIT_INTERNAL_ERROR if exit_code == EXIT_INTERNAL_ERROR else EXIT_OK


def main() -> int:
    reporter = Reporter()
    args: argparse.Namespace | None = None
    exit_code = EXIT_ERROR
    try:
        _require_windows()
        _configure_windows_apis()
        args = build_parser().parse_args()
        if args.wait < 3 or args.wait > 120:
            raise RecoveryError("--wait must be between 3 and 120 seconds.")
        if args.self_check:
            exit_code = EXIT_OK if historical_self_check(reporter) else EXIT_ERROR
        elif args.trace:
            exit_code = trace_auto_recovery_events(reporter, args.minutes)
        elif args.automation_status:
            exit_code = show_auto_recovery_status(reporter)
        elif args.event_triggered and not is_admin():
            raise RecoveryError(
                "The scheduled task is not running elevated; reinstall automatic recovery "
                "from an administrator account."
            )
        elif not is_admin() and not args.no_elevate:
            if args.elevated:
                raise RecoveryError("Elevation completed without an administrator token.")
            reporter.emit("UAC", "Requesting administrator access to inspect Appinfo's Job handles.")
            relaunch_elevated()
            exit_code = EXIT_OK
        elif not is_admin():
            raise RecoveryError("Administrator access is required to inspect Appinfo's Job handles.")
        elif args.install_automation:
            install_auto_recovery(reporter)
            exit_code = EXIT_OK
        elif args.remove_automation:
            remove_auto_recovery(reporter)
            exit_code = EXIT_OK
        else:
            enable_debug_privilege()
            exit_code = run(args, reporter)
    except SafetyStop as exc:
        reporter.emit("SAFETY STOP", str(exc))
        exit_code = EXIT_SAFETY_STOP
    except (RecoveryError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        reporter.emit("ERROR", str(exc))
        exit_code = EXIT_ERROR
    except Exception:  # noqa: BLE001 - last resort so the failure reaches last-run.log
        reporter.emit("INTERNAL ERROR", traceback.format_exc().strip())
        exit_code = EXIT_INTERNAL_ERROR
    finally:
        try:
            log_path = reporter.save()
            if log_path is not None and sys.stdout is not None:
                print(f"[LOG] {log_path}", flush=True)
        except OSError as exc:
            if sys.stderr is not None:
                print(f"[LOG ERROR] {exc}", file=sys.stderr, flush=True)
        if args is not None and args.pause and (is_admin() or args.self_check or args.no_elevate):
            _pause()
    if args is not None and args.event_triggered:
        return event_triggered_exit_code(exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
