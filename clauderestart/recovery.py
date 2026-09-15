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
from typing import Iterable, Protocol

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


class MembershipChanged(RuntimeError):
    """Members left the Job during validation, so the attempt must start again."""

    def __init__(self, exited: Iterable[int]) -> None:
        self.exited = sorted(exited)
        super().__init__(f"member(s) exited during validation: {self.exited}")


class JobInspector(Protocol):
    """Everything the repair does to a Job, behind one interface.

    Real termination and real kernel limits sit behind this, so the race fixtures and
    the failure-injection tests drive the same driver without terminating anything.
    """

    def pids(self, job: JobRecord) -> list[int]: ...

    def process_info(self, pid: int) -> ProcessInfo: ...

    def current_session(self) -> int | None: ...

    def duplicate_for_freeze(self, job: JobRecord) -> int: ...

    def query_limits(self, handle: int) -> bytes: ...

    def set_active_process_limit(self, handle: int, count: int) -> None: ...

    def restore_limits(self, handle: int, saved: bytes) -> None: ...

    def accounting(self, handle: int) -> int: ...

    def terminate(self, job: JobRecord) -> None: ...

    def close(self, handle: int) -> None: ...


class WindowsJobInspector:
    """The real kernel behind the interface above."""

    def pids(self, job: JobRecord) -> list[int]:
        return query_job_pids(job.handle)

    def process_info(self, pid: int) -> ProcessInfo:
        return _native_process_info(pid)

    def current_session(self) -> int | None:
        return _process_session_id(os.getpid())

    def duplicate_for_freeze(self, job: JobRecord) -> int:
        return winapi.duplicate_own_handle(
            job.handle,
            winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE | winapi.JOB_OBJECT_SET_ATTRIBUTES,
        )

    def query_limits(self, handle: int) -> bytes:
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        returned = wintypes.DWORD()
        ctypes.set_last_error(0)
        if not winapi.kernel32.QueryInformationJobObject(
            wintypes.HANDLE(handle),
            winapi.JOB_CLASS_EXTENDED_LIMIT,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
            ctypes.byref(returned),
        ):
            raise winapi.winerror("QueryInformationJobObject(extended limits)")
        return bytes(memoryview(limits).cast("B"))

    def set_active_process_limit(self, handle: int, count: int) -> None:
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(self.query_limits(handle))
        limits.BasicLimitInformation.LimitFlags |= winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        limits.BasicLimitInformation.ActiveProcessLimit = count
        ctypes.set_last_error(0)
        if not winapi.kernel32.SetInformationJobObject(
            wintypes.HANDLE(handle), winapi.JOB_CLASS_EXTENDED_LIMIT, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise winapi.winerror("SetInformationJobObject(active process limit)")

    def restore_limits(self, handle: int, saved: bytes) -> None:
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(saved)
        ctypes.set_last_error(0)
        if not winapi.kernel32.SetInformationJobObject(
            wintypes.HANDLE(handle), winapi.JOB_CLASS_EXTENDED_LIMIT, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise winapi.winerror("SetInformationJobObject(restore limits)")

    def accounting(self, handle: int) -> int:
        counters = winapi.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        ctypes.set_last_error(0)
        if not winapi.kernel32.QueryInformationJobObject(
            wintypes.HANDLE(handle),
            winapi.JOB_CLASS_BASIC_ACCOUNTING,
            ctypes.byref(counters),
            ctypes.sizeof(counters),
            ctypes.byref(returned),
        ):
            raise winapi.winerror("QueryInformationJobObject(accounting)")
        return int(counters.ActiveProcesses)

    def terminate(self, job: JobRecord) -> None:
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

    def close(self, handle: int) -> None:
        winapi.close_handle(handle)


def _require_terminate_access(job: JobRecord) -> None:
    required = winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE
    if job.granted_access & required != required:
        raise SafetyStop(
            f"Appinfo Job handle 0x{job.source_handle:X} lacks reviewed query/terminate access "
            f"(granted 0x{job.granted_access:X})."
        )


def validate_once(job: JobRecord, appinfo_pid: int, inspector: JobInspector) -> dict[int, int]:
    """Check every member of one Job snapshot, or refuse.

    Two snapshots bracket the per-process checks. A PID that appears between them means
    the Job grew while it was being validated, which no amount of retrying makes safe:
    the new member was never checked and would be terminated anyway. Members that leave
    are benign, and raise MembershipChanged so the caller can try again on the smaller
    set. Returns the validated PIDs with the creation time each was verified at, so a
    reused PID cannot pass a later check.
    """
    snapshot = set(inspector.pids(job))
    prohibited = {0, 4, os.getpid(), appinfo_pid}
    collision = prohibited.intersection(snapshot)
    if collision:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: protected/current PID(s) present: {sorted(collision)}."
        )
    session = inspector.current_session()
    details = {pid: inspector.process_info(pid) for pid in sorted(snapshot)}
    recheck = set(inspector.pids(job))
    added = recheck - snapshot
    if added:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: it gained member(s) {sorted(added)} while they were being "
            "checked, so they were never verified."
        )
    unverified = []
    for pid in sorted(recheck):
        info = details.get(pid)
        if info is None or session is None or info.session_id != session or info.creation_time is None:
            unverified.append(pid)
    if unverified:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: PID(s) could not be verified in this user session: {unverified}."
        )
    if recheck != snapshot:
        raise MembershipChanged(snapshot - recheck)
    return {pid: int(details[pid].creation_time) for pid in sorted(recheck)}


def final_check(job: JobRecord, validated: dict[int, int], inspector: JobInspector) -> str:
    """Re-read membership immediately before termination. Returns DONE or RETRY."""
    final = set(inspector.pids(job))
    added = final - set(validated)
    if added:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: member(s) {sorted(added)} appeared after validation."
        )
    details = {pid: inspector.process_info(pid) for pid in sorted(final)}
    recheck = set(inspector.pids(job))
    added = recheck - set(validated)
    if added:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: member(s) {sorted(added)} appeared after validation."
        )
    for pid in sorted(recheck):
        info = details.get(pid)
        if info is None or info.creation_time is None:
            raise SafetyStop(
                f"Refusing to terminate {job.name}: PID {pid} could not be verified immediately before "
                "termination."
            )
        if int(info.creation_time) != validated[pid]:
            raise SafetyStop(
                f"Refusing to terminate {job.name}: PID {pid} is no longer the process that was validated "
                "(the number was reused)."
            )
    return "DONE" if recheck == set(validated) else "RETRY"


def repair_stale_job(
    job: JobRecord,
    appinfo_pid: int,
    reporter: Reporter,
    inspector: JobInspector | None = None,
    attempts: int = 3,
) -> int:
    """Validate, freeze, re-check, then terminate exactly one stale Job.

    One budget covers the whole repair: a member leaving during validation and a member
    leaving after it both consume one attempt. Membership is frozen with an
    active-process limit before the final check, so the Job cannot grow between that
    check and the termination; the limit is always restored and the extra handle always
    closed, whatever happens.
    """
    inspector = inspector or WindowsJobInspector()
    _require_terminate_access(job)
    try:
        freeze_handle = inspector.duplicate_for_freeze(job)
    except (RecoveryError, OSError) as exc:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: its membership cannot be frozen ({exc}), so a process could "
            "join between the last check and the termination."
        ) from exc

    saved = inspector.query_limits(freeze_handle)
    applied = False
    try:
        for attempt in range(1, attempts + 1):
            try:
                validated = validate_once(job, appinfo_pid, inspector)
            except MembershipChanged as change:
                reporter.emit(
                    "NOTE", f"{len(change.exited)} member(s) of {job.name} exited during validation: {change.exited}."
                )
                continue
            job.pids = sorted(validated)
            reporter.emit(
                "REVALIDATED",
                f"{job.name} has {len(validated)} live member(s), all in this user session.",
            )
            try:
                inspector.set_active_process_limit(freeze_handle, len(validated))
            except (RecoveryError, OSError) as exc:
                raise SafetyStop(
                    f"Refusing to terminate {job.name}: its membership could not be frozen ({exc}), so a "
                    "process could join between the last check and the termination."
                ) from exc
            applied = True
            reporter.emit(
                "FREEZE",
                f"{job.name} is limited to its {len(validated)} validated member(s), so it cannot grow.",
            )
            if final_check(job, validated, inspector) == "RETRY":
                reporter.emit("NOTE", f"A member of {job.name} exited before termination; checking again.")
                continue
            inspector.terminate(job)
            reporter.emit("CLOSED", f"Terminated the exact stale Job and its {len(validated)} member(s).")
            return len(validated)
        raise SafetyStop(
            f"Refusing to terminate {job.name}: its membership kept changing over {attempts} attempts."
        )
    finally:
        problems = []
        if applied:
            try:
                inspector.restore_limits(freeze_handle, saved)
            except (RecoveryError, OSError) as exc:
                problems.append(str(exc))
        try:
            inspector.close(freeze_handle)
        except (RecoveryError, OSError) as exc:
            problems.append(str(exc))
        if problems:
            # Reported, never raised: this must not mask the outcome above.
            reporter.emit("ERROR", f"Could not tidy up after {job.name}: " + "; ".join(problems))


def probe_freeze(job: JobRecord, inspector: JobInspector | None = None) -> dict[str, object]:
    """Read-only: can this Job's membership be frozen, and what are its limits now?

    A stale Job exists only during an incident, so --scan runs this on every Claude Job,
    current ones included, to answer that question before an incident happens.
    """
    inspector = inspector or WindowsJobInspector()
    try:
        handle = inspector.duplicate_for_freeze(job)
    except (RecoveryError, OSError) as exc:
        return {"available": False, "error": str(exc), "active": None, "limit": None}
    try:
        limits = winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(inspector.query_limits(handle))
        return {
            "available": True,
            "error": "",
            "active": inspector.accounting(handle),
            "limit": int(limits.BasicLimitInformation.ActiveProcessLimit)
            if limits.BasicLimitInformation.LimitFlags & winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            else None,
        }
    except (RecoveryError, OSError) as exc:
        return {"available": False, "error": str(exc), "active": None, "limit": None}
    finally:
        inspector.close(handle)


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
    aumid = package.aumid
    if aumid is None:
        # Defensive: cli.run refuses earlier, so reaching this is a programming error.
        raise RecoveryError(
            f"Cannot launch Claude: the application id could not be established "
            f"({package.application_id_error})."
        )
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

    race_passed, race_total = _race_self_check(reporter)

    reporter.emit(
        "SELF-CHECK",
        f"Production classifier selected only the older Job in {passed}/{len(fixtures)} incidents; "
        f"all {safety_checks}/3 current/newer/wrong-user guards passed; member counts ranged from "
        f"{min(item[2] for item in fixtures)} to {max(item[2] for item in fixtures)}; "
        f"race guards {race_passed}/{race_total}.",
    )
    return passed == len(fixtures) and safety_checks == 3 and race_passed == race_total


def _race_self_check(reporter: Reporter) -> tuple[int, int]:
    """Run the membership-race fixtures through the real repair driver.

    These use the same repair_stale_job that runs during an incident, so a change that
    weakened the checks would fail here, in every build and on every machine.
    """
    from .fakes import FakeJobInspector  # imported here so the package has no import cycle

    quiet = Reporter()
    quiet.emit = lambda *_args, **_kwargs: None  # type: ignore[assignment]
    job = lambda: JobRecord(  # noqa: E731 - a fresh record per fixture
        9,
        9,
        0x1234,
        winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE,
        r"\Container_Claude_1.0.0.0_x64__pzs8sxrjxfjjc-S-1-5-21-1-2-3-1001",
        [101, 102],
    )
    passed = 0
    total = 5

    # 1. A PID appears between the two validation snapshots: never validated, so stop.
    grew = FakeJobInspector([[101, 102], [101, 102, 103]])
    try:
        repair_stale_job(job(), 4242, quiet, grew)
    except SafetyStop:
        passed += int(grew.terminate_calls == 0)

    # 2. A validated PID is replaced by the same number with a different start time.
    reused = FakeJobInspector(
        [[101, 102], [101, 102], [101, 102], [101, 102]],
        info={
            # Validation sees one start time; the check before termination sees another,
            # which is what a reused process number looks like.
            102: [
                ProcessInfo(102, "claude.exe", "", "", 1, 5),
                ProcessInfo(102, "claude.exe", "", "", 1, 99),
            ]
        },
    )
    try:
        repair_stale_job(job(), 4242, quiet, reused)
    except SafetyStop:
        passed += int(reused.terminate_calls == 0)

    # 3. A member exits during validation: retry, then terminate the remaining set.
    shrank = FakeJobInspector([[101, 102], [101], [101], [101], [101], [101]])
    try:
        closed = repair_stale_job(job(), 4242, quiet, shrank)
        passed += int(closed == 1 and shrank.terminate_calls == 1)
    except SafetyStop:
        pass

    # 4. A PID appears after validation, before the final snapshot.
    late = FakeJobInspector([[101, 102], [101, 102], [101, 102, 103]])
    try:
        repair_stale_job(job(), 4242, quiet, late)
    except SafetyStop:
        passed += int(late.terminate_calls == 0)

    # 5. A member exits after validation: retry, and the freeze is restored each time.
    exited_late = FakeJobInspector([[101, 102], [101, 102], [101], [101], [101], [101], [101], [101]])
    try:
        closed = repair_stale_job(job(), 4242, quiet, exited_late)
        passed += int(closed == 1 and exited_late.terminate_calls == 1 and bool(exited_late.restore_calls))
    except SafetyStop:
        pass

    return passed, total
