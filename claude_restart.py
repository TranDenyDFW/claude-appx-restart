#!/usr/bin/env python3
"""Safely repair Claude Desktop's stale AppX Job and start Claude.

This utility targets one verified failure mode: Appinfo retaining a versioned
Container_Claude Job from an older installed package. It never searches for or
kills processes by executable name. Instead, it duplicates the exact kernel
Job handle held by Appinfo, displays the Job's current members, terminates that
Job only when its identity and older version are unambiguous, then launches and
verifies the currently installed Claude package.

Python 3.10+; Windows only; no third-party packages.
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
import subprocess
import sys
import time
from typing import Iterable
import xml.etree.ElementTree as ET


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
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
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

    def save(self) -> Path:
        target = Path(__file__).resolve().with_name("last-run.log")
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        target.write_text(stamp + "\n" + "\n".join(self.lines) + "\n", encoding="utf-8")
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


def relaunch_elevated() -> None:
    script = str(Path(__file__).resolve())
    forwarded = [arg for arg in sys.argv[1:] if arg != "--elevated"]
    parameters = subprocess.list2cmdline([script, *forwarded, "--elevated"])
    result = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        parameters,
        str(Path(script).parent),
        SW_SHOWNORMAL,
    )
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
            return ctypes.wstring_at(value.Buffer, value.Length // ctypes.sizeof(ctypes.c_wchar))
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


def validate_live_members(job: JobRecord, appinfo_pid: int) -> list[ProcessInfo]:
    live_pids = query_job_pids(job.handle)
    prohibited = {0, 4, os.getpid(), appinfo_pid}
    collision = prohibited.intersection(live_pids)
    if collision:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: protected/current PID(s) present: {sorted(collision)}."
        )
    current_session = _process_session_id(os.getpid())
    details = process_details(live_pids)
    bad_sessions = [
        info.pid
        for info in details
        if info.session_id is None or current_session is None or info.session_id != current_session
    ]
    if bad_sessions:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: PID(s) are not verified in this user session: "
            f"{bad_sessions}."
        )
    job.pids = live_pids
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


def build_task_action(python_executable: Path, script_path: Path) -> str:
    return (
        f'"{python_executable}" "{script_path}" '
        "--event-triggered --yes --wait 30"
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


def _task_python_executable() -> Path:
    executable = Path(sys.executable).resolve()
    pythonw = executable.with_name("pythonw.exe")
    return pythonw if pythonw.is_file() else executable


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
    LastRunTime = if ($info) {{ $info.LastRunTime.ToString('o') }} else {{ '' }}
    LastTaskResult = if ($info) {{ $info.LastTaskResult }} else {{ $null }}
}} | ConvertTo-Json -Compress -Depth 4
"""
    raw = _run_powershell(script)
    return dict(json.loads(raw))


def install_auto_recovery(reporter: Reporter) -> None:
    package = get_claude_package()
    script_path = Path(__file__).resolve()
    python_executable = _task_python_executable()
    action = build_task_action(python_executable, script_path)
    command = [
        "schtasks.exe",
        "/Create",
        "/TN",
        AUTO_RECOVERY_TASK_NAME,
        "/TR",
        action,
        "/SC",
        "ONEVENT",
        "/EC",
        APPMODEL_LOG,
        "/MO",
        AUTO_RECOVERY_XPATH,
        "/RL",
        "HIGHEST",
        "/IT",
        "/F",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RecoveryError(f"Could not register {AUTO_RECOVERY_TASK_NAME}: {detail}")

    status = automation_task_status()
    expected_arguments = f'"{script_path}" --event-triggered --yes --wait 30'
    valid = (
        status.get("Installed") is True
        and status.get("MultipleInstances") == "IgnoreNew"
        and status.get("LogonType") in ("Interactive", "InteractiveToken")
        and status.get("RunLevel") in ("Highest", "HighestAvailable")
        and status.get("Subscription")
        and AUTO_RECOVERY_APPLICATION in str(status.get("Subscription"))
        and SHARE_VIOLATION_DECIMAL in str(status.get("Subscription"))
        and os.path.normcase(str(status.get("Execute")).strip('"'))
        == os.path.normcase(str(python_executable))
        and str(status.get("Arguments")) == expected_arguments
    )
    if not valid:
        subprocess.run(
            ["schtasks.exe", "/Delete", "/TN", AUTO_RECOVERY_TASK_NAME, "/F"],
            capture_output=True,
            check=False,
        )
        raise SafetyStop("The registered task did not preserve the reviewed trigger/action settings; it was removed.")
    reporter.emit(
        "INSTALLED",
        f"Task '{AUTO_RECOVERY_TASK_NAME}' watches Event 208 for {AUTO_RECOVERY_APPLICATION} / "
        f"{SHARE_VIOLATION_HEX} and runs only while this user is logged on.",
    )
    reporter.emit("ACTION", f"{python_executable} -> {script_path}")
    reporter.emit("PACKAGE", f"Current package verified: {package.package_full_name}")


def remove_auto_recovery(reporter: Reporter) -> None:
    status = automation_task_status()
    if not status.get("Installed"):
        reporter.emit("NOT INSTALLED", f"Task '{AUTO_RECOVERY_TASK_NAME}' is already absent.")
        return
    completed = subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", AUTO_RECOVERY_TASK_NAME, "/F"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
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
    reporter.emit(
        "LAST RUN",
        f"{status.get('LastRunTime') or 'never'}; result={status.get('LastTaskResult')}",
    )
    return 0


def appmodel_share_violations(package: PackageInfo, since: datetime) -> list[dict[str, object]]:
    start = _ps_single_quote(since.isoformat())
    package_name = _ps_single_quote(package.package_full_name)
    log_name = _ps_single_quote(APPMODEL_LOG)
    script = f"""
$start = [DateTimeOffset]::Parse({start}).LocalDateTime
$package = {package_name}
$result = @(
    Get-WinEvent -FilterHashtable @{{LogName={log_name}; Id=208,215; StartTime=$start}} -ErrorAction SilentlyContinue |
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
    subprocess.Popen(
        ["explorer.exe", f"shell:AppsFolder\\{aumid}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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
            return 10 if stale else 0
        if args.event_triggered and not stale:
            reporter.emit(
                "NO ACTION",
                "The event matched, but no exact older Claude Job exists; automatic relaunch was suppressed.",
            )
            return 0
        if stale and not args.yes:
            if not sys.stdin.isatty():
                raise SafetyStop("Confirmation is required; rerun interactively or pass --yes.")
            answer = input("Type REPAIR to terminate only the verified stale Job member(s): ").strip()
            if answer != "REPAIR":
                reporter.emit("CANCELLED", "No processes were terminated.")
                return 2

        for job in stale:
            details = validate_live_members(job, appinfo_pid)
            reporter.emit(
                "REVALIDATED",
                f"{job.name} has {len(details)} live member(s), all in this user session.",
            )
            terminate_exact_job(job)
            reporter.emit("CLOSED", f"Terminated the exact stale Job and its {len(details)} member(s).")
    finally:
        close_job_records(jobs)

    if stale:
        time.sleep(0.5)
    return 0 if launch_and_verify(package, reporter, args.wait) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repair the verified stale Claude AppX Job failure and start Claude Desktop."
    )
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


def main() -> int:
    reporter = Reporter()
    exit_code = 1
    try:
        _require_windows()
        _configure_windows_apis()
        args = build_parser().parse_args()
        if args.wait < 3 or args.wait > 120:
            raise RecoveryError("--wait must be between 3 and 120 seconds.")
        if args.self_check:
            exit_code = 0 if historical_self_check(reporter) else 1
            return exit_code
        if args.trace:
            exit_code = trace_auto_recovery_events(reporter, args.minutes)
            return exit_code
        if args.automation_status:
            exit_code = show_auto_recovery_status(reporter)
            return exit_code
        if not is_admin() and not args.no_elevate:
            if args.elevated:
                raise RecoveryError("Elevation completed without an administrator token.")
            reporter.emit("UAC", "Requesting administrator access to inspect Appinfo's Job handles.")
            relaunch_elevated()
            return 0
        if not is_admin():
            raise RecoveryError("Administrator access is required to inspect Appinfo's Job handles.")
        if args.install_automation:
            install_auto_recovery(reporter)
            exit_code = 0
            return exit_code
        if args.remove_automation:
            remove_auto_recovery(reporter)
            exit_code = 0
            return exit_code
        enable_debug_privilege()
        exit_code = run(args, reporter)
        return exit_code
    except SafetyStop as exc:
        reporter.emit("SAFETY STOP", str(exc))
        exit_code = 2
        return exit_code
    except (RecoveryError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        reporter.emit("ERROR", str(exc))
        exit_code = 1
        return exit_code
    finally:
        try:
            log_path = reporter.save()
            if reporter.lines and sys.stdout is not None:
                print(f"[LOG] {log_path}", flush=True)
        except OSError as exc:
            if sys.stderr is not None:
                print(f"[LOG ERROR] {exc}", file=sys.stderr, flush=True)
        if "args" in locals() and args.pause and (is_admin() or args.self_check or args.no_elevate):
            try:
                input("Press Enter to close...")
            except EOFError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
