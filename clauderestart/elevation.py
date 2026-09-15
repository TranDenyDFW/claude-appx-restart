"""Administrator elevation: the UAC relaunch and the debug privilege."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import subprocess
import sys

from . import payload, winapi
from .errors import RecoveryError
from .reporting import Reporter, app_location, log_fingerprint
from .task import launcher_command


def elevation_request(argv: list[str]) -> tuple[str, str, str]:
    """Return (target, parameters, working directory) for the ShellExecute runas relaunch."""
    forwarded = [arg for arg in argv if arg != "--elevated"]
    executable, prefix = launcher_command()
    parts = ([prefix.strip('"')] if prefix else []) + forwarded + ["--elevated"]
    return str(executable), subprocess.list2cmdline(parts), str(app_location())


def relaunch_elevated(reporter: Reporter | None = None) -> int:
    """Re-run this tool elevated (one UAC prompt), wait for it, and return its exit code.

    Waiting lets the .cmd launchers and scripted callers see the elevated run's real
    result instead of the hand-off parent's.

    The parent keeps writing its own log until a child has actually run and left one.
    Every way the child can fail to start, including a cancelled prompt, a launch
    failure, a missing process handle, a failed wait and a failed exit code, therefore
    ends with a diagnostic on disk rather than silence.
    """
    log_path = app_location() / payload.LOG_FILE_NAME
    before = log_fingerprint(log_path)
    if reporter is not None:
        reporter.log_guard = before
    target, parameters, workdir = elevation_request(sys.argv[1:])
    if winapi.is_frozen():
        # PyInstaller (>= 6.9) must give the child its own extraction directory rather
        # than sharing the one that is deleted when this parent exits.
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    info = winapi.SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(winapi.SHELLEXECUTEINFOW)
    info.fMask = winapi.SEE_MASK_NOCLOSEPROCESS | winapi.SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = target
    info.lpParameters = parameters
    info.lpDirectory = workdir
    info.nShow = winapi.SW_SHOWNORMAL
    ctypes.set_last_error(0)
    if not winapi.shell32.ShellExecuteExW(ctypes.byref(info)):
        code = ctypes.get_last_error()
        if code == winapi.ERROR_CANCELLED:
            raise RecoveryError("The User Account Control prompt was cancelled; nothing was changed.")
        raise RecoveryError(f"Administrator elevation was not started: {ctypes.WinError(code)}")
    handle = int(info.hProcess or 0)
    if not handle:
        raise RecoveryError("Administrator elevation started, but Windows returned no process handle.")
    try:
        waited = winapi.kernel32.WaitForSingleObject(wintypes.HANDLE(handle), winapi.INFINITE)
        if int(waited) == winapi.WAIT_FAILED:
            raise winapi.winerror("WaitForSingleObject")
        exit_code = wintypes.DWORD()
        if not winapi.kernel32.GetExitCodeProcess(wintypes.HANDLE(handle), ctypes.byref(exit_code)):
            raise winapi.winerror("GetExitCodeProcess")
        code = int(exit_code.value)
    finally:
        winapi.close_handle(handle)
    if reporter is not None:
        if log_fingerprint(log_path) != before:
            # The child left its own result, so the parent's hand-off lines must not
            # replace it.
            reporter.persist = False
        else:
            reporter.emit(
                "ELEVATED",
                f"The administrator run finished with exit code {code}, but left no log beside this program. "
                "An over the shoulder elevation logs under the administrator account instead.",
            )
    return code


def enable_debug_privilege() -> None:
    token = wintypes.HANDLE()
    if not winapi.advapi32.OpenProcessToken(
        winapi.kernel32.GetCurrentProcess(),
        winapi.TOKEN_QUERY | winapi.TOKEN_ADJUST_PRIVILEGES,
        ctypes.byref(token),
    ):
        raise winapi.winerror("OpenProcessToken")
    try:
        luid = winapi.LUID()
        if not winapi.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            raise winapi.winerror("LookupPrivilegeValueW")
        privileges = winapi.TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = winapi.SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not winapi.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None):
            raise winapi.winerror("AdjustTokenPrivileges")
        if ctypes.get_last_error() == winapi.ERROR_NOT_ALL_ASSIGNED:
            raise RecoveryError("The elevated token does not contain SeDebugPrivilege.")
    finally:
        winapi.close_handle(int(token.value or 0))
