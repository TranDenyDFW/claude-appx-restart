"""Discovery, classification, validation, and termination of the stale Claude AppX Job.

The tool never searches for or kills processes by executable name. It duplicates the
exact kernel Job handle held by Appinfo, displays the Job's members, terminates that
Job only when its identity and older version are unambiguous, then launches and
verifies the currently installed Claude package.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Iterable

from . import events, shell, winapi
from .errors import RecoveryError, SafetyStop
from .package import EXPECTED_PACKAGE_FAMILY, PackageInfo, version_key
from .reporting import Reporter


APPINFO_SERVICE = "Appinfo"


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


def get_appinfo_pid() -> int:
    advapi32 = winapi.advapi32
    manager = advapi32.OpenSCManagerW(None, None, winapi.SC_MANAGER_CONNECT)
    if not manager:
        raise winapi.winerror("OpenSCManagerW")
    service = None
    try:
        service = advapi32.OpenServiceW(manager, APPINFO_SERVICE, winapi.SERVICE_QUERY_STATUS)
        if not service:
            raise winapi.winerror("OpenServiceW(Appinfo)")
        status = winapi.SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        ok = advapi32.QueryServiceStatusEx(
            service,
            winapi.SC_STATUS_PROCESS_INFO,
            ctypes.cast(ctypes.byref(status), ctypes.POINTER(wintypes.BYTE)),
            ctypes.sizeof(status),
            ctypes.byref(needed),
        )
        if not ok:
            raise winapi.winerror("QueryServiceStatusEx(Appinfo)")
        return int(status.dwProcessId)
    finally:
        if service:
            winapi.close_handle(int(service))
        winapi.close_handle(int(manager))


def _system_handles() -> list[winapi.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]:
    size = 1 << 20
    while size <= (1 << 29):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = int(
            winapi.ntdll.NtQuerySystemInformation(
                winapi.SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            )
        )
        unsigned = status & 0xFFFFFFFF
        if status >= 0:
            count = ctypes.c_size_t.from_buffer(buffer, 0).value
            offset = ctypes.sizeof(ctypes.c_size_t) * 2
            entry_size = ctypes.sizeof(winapi.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            required = offset + count * entry_size
            if required > size:
                raise RecoveryError("NtQuerySystemInformation returned an invalid handle count.")
            return [
                winapi.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer_copy(buffer, offset + index * entry_size)
                for index in range(count)
            ]
        if unsigned in (0xC0000004, 0xC0000023, 0x80000005):
            size = max(size * 2, int(needed.value) + 65536)
            continue
        raise RecoveryError(f"NtQuerySystemInformation failed with NTSTATUS 0x{unsigned:08X}.")
    raise RecoveryError("System handle table exceeded the 512 MiB safety ceiling.")


def _job_object_type_index() -> int:
    handle = winapi.kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise winapi.winerror("CreateJobObjectW")
    handle_value = int(handle)
    try:
        for entry in _system_handles():
            if int(entry.UniqueProcessId) == os.getpid() and int(entry.HandleValue) == handle_value:
                return int(entry.ObjectTypeIndex)
    finally:
        winapi.close_handle(handle_value)
    raise RecoveryError("Could not identify the Windows Job object type index.")


def _query_object_name(handle: int) -> str | None:
    size = 4096
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = int(
            winapi.ntdll.NtQueryObject(
                wintypes.HANDLE(handle),
                winapi.OBJECT_NAME_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            )
        )
        if status >= 0:
            value = winapi.UNICODE_STRING.from_buffer_copy(buffer)
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
        ok = winapi.kernel32.QueryInformationJobObject(
            wintypes.HANDLE(handle),
            winapi.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
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
        if ctypes.get_last_error() == winapi.ERROR_MORE_DATA:
            capacity *= 4
            continue
        raise winapi.winerror("QueryInformationJobObject")
    raise RecoveryError("Claude Job contained more process IDs than the safety ceiling permits.")


def discover_claude_jobs(appinfo_pid: int) -> list[JobRecord]:
    if not appinfo_pid:
        return []
    kernel32 = winapi.kernel32
    job_type = _job_object_type_index()
    handles = _system_handles()
    candidates: dict[int, winapi.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX] = {}
    for entry in handles:
        if int(entry.UniqueProcessId) != appinfo_pid or int(entry.ObjectTypeIndex) != job_type:
            continue
        object_address = int(entry.Object or 0)
        old = candidates.get(object_address)
        score = int(bool(entry.GrantedAccess & winapi.JOB_OBJECT_QUERY)) + int(
            bool(entry.GrantedAccess & winapi.JOB_OBJECT_TERMINATE)
        )
        old_score = -1 if old is None else int(bool(old.GrantedAccess & winapi.JOB_OBJECT_QUERY)) + int(
            bool(old.GrantedAccess & winapi.JOB_OBJECT_TERMINATE)
        )
        if old is None or score > old_score:
            candidates[object_address] = entry

    owner = kernel32.OpenProcess(winapi.PROCESS_DUP_HANDLE, False, appinfo_pid)
    if not owner:
        raise winapi.winerror(f"OpenProcess(Appinfo PID {appinfo_pid})")
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
                winapi.DUPLICATE_SAME_ACCESS,
            ):
                continue
            duplicate_value = int(duplicate.value or 0)
            name = _query_object_name(duplicate_value)
            if not name or "Container_Claude_" not in name:
                winapi.close_handle(duplicate_value)
                continue
            try:
                pids = query_job_pids(duplicate_value)
            except Exception:
                winapi.close_handle(duplicate_value)
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
        winapi.close_handle(int(owner))
    return sorted(records, key=lambda record: record.name)


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
        raise SafetyStop("Claude-like Job identity did not fit the reviewed older/current rule:\n  " + rendered)
    return stale, current


def _process_session_id(pid: int) -> int | None:
    session = wintypes.DWORD()
    ctypes.set_last_error(0)
    if not winapi.kernel32.ProcessIdToSessionId(pid, ctypes.byref(session)):
        return None
    return int(session.value)


def _native_process_info(pid: int) -> ProcessInfo:
    kernel32 = winapi.kernel32
    session = _process_session_id(pid)
    handle = kernel32.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ProcessInfo(pid, "<exited or inaccessible>", "", "", session, None)
    try:
        path_buffer = ctypes.create_unicode_buffer(32768)
        path_size = wintypes.DWORD(len(path_buffer))
        path = ""
        if kernel32.QueryFullProcessImageNameW(handle, 0, path_buffer, ctypes.byref(path_size)):
            path = path_buffer.value
        created = winapi.FILETIME()
        exited = winapi.FILETIME()
        kernel = winapi.FILETIME()
        user = winapi.FILETIME()
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
        winapi.close_handle(int(handle))


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
        raw = shell.run_powershell(script, timeout=20)
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
    details: Iterable[ProcessInfo], current_session: int | None, still_in_job: Iterable[int]
) -> tuple[list[int], list[int]]:
    """Split Job members into (exited, unverified) PIDs.

    A member counts as exited only when its session and process could not be opened
    AND the kernel no longer lists it in the Job (a fresh JobObjectBasicProcessIdList
    snapshot). A member the kernel still lists but that cannot be verified in this
    session is unverified, which stops the repair: the Job is never terminated on an
    inference.
    """
    remaining = set(still_in_job)
    exited: list[int] = []
    unverified: list[int] = []
    for info in details:
        opaque = info.session_id is None and info.name == "<exited or inaccessible>"
        if opaque and info.pid not in remaining:
            exited.append(info.pid)
        elif current_session is None or info.session_id is None or info.session_id != current_session:
            unverified.append(info.pid)
    return exited, unverified


def validate_live_members(job: JobRecord, appinfo_pid: int, reporter: Reporter | None = None) -> list[ProcessInfo]:
    live_pids = query_job_pids(job.handle)
    prohibited = {0, 4, os.getpid(), appinfo_pid}
    collision = prohibited.intersection(live_pids)
    if collision:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: protected/current PID(s) present: {sorted(collision)}."
        )
    current_session = _process_session_id(os.getpid())
    details = process_details(live_pids)
    exited, unverified = _partition_members(details, current_session, query_job_pids(job.handle))
    if unverified:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: PID(s) could not be verified in this user session: {unverified}."
        )
    if exited and reporter is not None:
        reporter.emit("NOTE", f"{len(exited)} member(s) of {job.name} exited before validation: {exited}.")
    job.pids = [pid for pid in live_pids if pid not in exited]
    return details


def terminate_exact_job(job: JobRecord) -> None:
    required = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE
    if job.granted_access & required != required:
        raise SafetyStop(
            f"Appinfo Job handle 0x{job.source_handle:X} lacks reviewed query/terminate access "
            f"(granted 0x{job.granted_access:X})."
        )
    ctypes.set_last_error(0)
    if not winapi.kernel32.TerminateJobObject(wintypes.HANDLE(job.handle), 0xC0DE):
        raise winapi.winerror(f"TerminateJobObject({job.name})")
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if not query_job_pids(job.handle):
            return
        time.sleep(0.2)
    survivors = query_job_pids(job.handle)
    raise RecoveryError(f"The stale Job still reports member PID(s) after termination: {survivors}.")


def close_job_records(jobs: Iterable[JobRecord]) -> None:
    for job in jobs:
        winapi.close_handle(job.handle)
        job.handle = 0


def _window_process_path(pid: int) -> str:
    kernel32 = winapi.kernel32
    handle = kernel32.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        winapi.close_handle(int(handle))


def visible_claude_windows(package: PackageInfo) -> list[dict[str, object]]:
    user32 = winapi.user32
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
            found.append({"hwnd": int(hwnd), "pid": int(pid.value), "title": title_buffer.value, "path": path})
        return True

    if not user32.EnumWindows(visit, 0):
        raise winapi.winerror("EnumWindows")
    return found


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
        **shell.NO_WINDOW,
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
        violations = events.appmodel_share_violations(package, started_at)
        event_check = "complete"
    except Exception as exc:
        violations = []
        event_check = f"unavailable: {exc}"

    if violations:
        ids = ", ".join(str(event.get("Id")) for event in violations)
        reporter.emit(
            "RED",
            f"Claude logged {len(violations)} new {events.SHARE_VIOLATION_HEX} AppModel event(s); IDs: {ids}.",
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
            f"Visible Claude window verified at PID {window['pid']}; zero new {events.SHARE_VIOLATION_HEX} events.",
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
    access = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE
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
            access,
            rf"\Container_Claude_{current_version}{suffix}-{sid}",
            list(range(100, 100 + members)),
        )
        older_job = JobRecord(
            2,
            2,
            0,
            access,
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
    current_only = JobRecord(3, 3, 0, access, rf"\Container_Claude_{base_version}{suffix}-{sid}", [])
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
