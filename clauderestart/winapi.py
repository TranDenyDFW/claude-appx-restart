"""Windows API bindings shared by the clauderestart package.

A leaf module: it imports only clauderestart.errors. Other modules write
`from . import winapi` and read attributes such as `winapi.kernel32` and
`winapi.is_frozen()` at call time, so a test patches exactly one place.
"""

from __future__ import annotations

import collections
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys
import uuid

from .errors import RecoveryError


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
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
ERROR_CANCELLED = 1223
INFINITE = 0xFFFFFFFF
FOLDERID_PROGRAM_FILES = "{905e63b6-c1bf-494e-b29c-65b732d3d21a}"

# File handles. A file opened with only FILE_SHARE_READ cannot be written, renamed,
# or deleted by anyone else while the handle is open, which is how bytes that were
# hashed stay the bytes that are used.
GENERIC_READ = 0x80000000
READ_CONTROL = 0x00020000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_NAME_NORMALIZED = 0x0
VOLUME_NAME_DOS = 0x0
FILE_ATTRIBUTE_TAG_INFO = 9
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
LONG_PATH_PREFIX = "\\\\?\\"
LONG_PATH_UNC_PREFIX = "\\\\?\\UNC\\"

# Security descriptors, ACLs, and the access bits that amount to write access.
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SDDL_REVISION_1 = 1
SE_DACL_PRESENT = 0x0004
SE_DACL_PROTECTED = 0x1000
ACL_SIZE_INFORMATION_CLASS = 2
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_DENIED_ACE_TYPE = 0x01
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
DELETE = 0x00010000
READ_CONTROL_RIGHT = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_WRITE_EA = 0x00000010
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_DELETE_CHILD = 0x00000040
GENERIC_WRITE_MASK = 0x40000000
GENERIC_ALL_MASK = 0x10000000
MAXIMUM_ALLOWED = 0x02000000
FILE_ALL_ACCESS = 0x001F01FF
FILE_GENERIC_READ_EXECUTE = 0x001200A9
SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"
SE_RESTORE_NAME = "SeRestorePrivilege"
SE_DEBUG_NAME = "SeDebugPrivilege"


if os.name == "nt":
    ole32 = ctypes.WinDLL("ole32")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    version = ctypes.WinDLL("version", use_last_error=True)


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


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_string(cls, text: str) -> "GUID":
        value = uuid.UUID(text)
        guid = cls()
        guid.Data1, guid.Data2, guid.Data3 = value.fields[0], value.fields[1], value.fields[2]
        for index, byte in enumerate(value.bytes[8:]):
            guid.Data4[index] = byte
        return guid


class SHELLEXECUTEINFOW(ctypes.Structure):
    # 112 bytes on x64; hIconOrMonitor stands in for the hIcon/hMonitor union.
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def configure() -> None:
    """Declare argument and return types for every Windows API the package calls."""
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
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

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

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL

    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.UINT),
    ]
    version.VerQueryValueW.restype = wintypes.BOOL

    # These two report failure through their RETURN VALUE (ERROR_SUCCESS or a Win32
    # code), the opposite of the BOOL APIs above, so they are never wrapped with the
    # "if not fn(): raise" idiom.
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL


def is_frozen() -> bool:
    """Return True inside a PyInstaller executable (read at call time; tests patch this)."""
    return bool(getattr(sys, "frozen", False))


def require_windows() -> None:
    if os.name != "nt":
        raise RecoveryError("This utility only runs on Windows.")


def winerror(operation: str) -> RecoveryError:
    code = ctypes.get_last_error()
    return RecoveryError(f"{operation} failed: {ctypes.WinError(code)}")


def close_handle(handle: int | None) -> None:
    if handle:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def is_admin() -> bool:
    return bool(shell32.IsUserAnAdmin())


class FILE_ATTRIBUTE_TAG_INFORMATION(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    # Every non-object ACE type shares this prefix: header, mask, then the SID.
    _fields_ = [("Header", ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


AceEntry = collections.namedtuple("AceEntry", "index type flags mask sid")
SecurityInfo = collections.namedtuple("SecurityInfo", "owner control aces")


def sid_to_string(sid_pointer: object) -> str:
    """Convert a SID pointer to its S-1-... form, or an empty string."""
    if not sid_pointer or not advapi32.IsValidSid(ctypes.c_void_p(sid_pointer)):
        return ""
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_pointer), ctypes.byref(text)):
        return ""
    try:
        return str(text.value or "")
    finally:
        kernel32.LocalFree(ctypes.cast(text, wintypes.HLOCAL))


def _dacl_entries(dacl: object) -> list[AceEntry]:
    """Read every ACE of a DACL, keeping the raw type so unknown types stay visible."""
    if not dacl:
        return []
    sizes = ACL_SIZE_INFORMATION()
    if not advapi32.GetAclInformation(
        ctypes.c_void_p(dacl), ctypes.byref(sizes), ctypes.sizeof(sizes), ACL_SIZE_INFORMATION_CLASS
    ):
        raise winerror("GetAclInformation")
    entries: list[AceEntry] = []
    for index in range(int(sizes.AceCount)):
        ace_pointer = ctypes.c_void_p()
        if not advapi32.GetAce(ctypes.c_void_p(dacl), index, ctypes.byref(ace_pointer)):
            raise winerror(f"GetAce({index})")
        header = ACE_HEADER.from_address(ace_pointer.value)
        ace_type = int(header.AceType)
        flags = int(header.AceFlags)
        mask = 0
        sid = ""
        if ace_type in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
            ace = ACCESS_ALLOWED_ACE.from_address(ace_pointer.value)
            mask = int(ace.Mask)
            sid = sid_to_string(ace_pointer.value + ACCESS_ALLOWED_ACE.SidStart.offset)
        entries.append(AceEntry(index, ace_type, flags, mask, sid))
    return entries


def read_security(handle: int) -> SecurityInfo:
    """Read owner, control flags, and every DACL entry through an open handle."""
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    code = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if code != 0:
        raise RecoveryError(f"GetSecurityInfo failed: {ctypes.WinError(code)}")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise winerror("GetSecurityDescriptorControl")
        return SecurityInfo(sid_to_string(owner.value), int(control.value), _dacl_entries(dacl.value))
    finally:
        if descriptor.value:
            kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def security_descriptor_from_sddl(sddl: str) -> ctypes.c_void_p:
    """Build a security descriptor from an SDDL string; the caller frees it."""
    descriptor = ctypes.c_void_p()
    size = wintypes.ULONG()
    ctypes.set_last_error(0)
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise winerror("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    return descriptor


def read_sddl_security(sddl: str) -> SecurityInfo:
    """Parse an SDDL string the same way a real object is read (used by tests)."""
    descriptor = security_descriptor_from_sddl(sddl)
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise winerror("GetSecurityDescriptorControl")
        present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise winerror("GetSecurityDescriptorDacl")
        owner = ctypes.c_void_p()
        owner_defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)):
            raise winerror("GetSecurityDescriptorOwner")
        entries = _dacl_entries(dacl.value) if present.value else []
        return SecurityInfo(sid_to_string(owner.value), int(control.value), entries)
    finally:
        kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def apply_security_from_sddl(handle: int, sddl: str, *, owner: bool = True) -> None:
    """Write the owner and a protected DACL from an SDDL string onto an open handle."""
    descriptor = security_descriptor_from_sddl(sddl)
    try:
        present = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise winerror("GetSecurityDescriptorDacl")
        owner_sid = ctypes.c_void_p()
        owner_defaulted = wintypes.BOOL()
        if owner and not advapi32.GetSecurityDescriptorOwner(
            descriptor, ctypes.byref(owner_sid), ctypes.byref(owner_defaulted)
        ):
            raise winerror("GetSecurityDescriptorOwner")
        information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        if owner:
            information |= OWNER_SECURITY_INFORMATION
        code = advapi32.SetSecurityInfo(
            wintypes.HANDLE(handle),
            SE_FILE_OBJECT,
            information,
            owner_sid if owner else None,
            None,
            dacl,
            None,
        )
        if code != 0:
            raise RecoveryError(f"SetSecurityInfo failed: {ctypes.WinError(code)}")
    finally:
        kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def enable_privilege(name: str) -> None:
    """Enable one privilege in this process token, or raise."""
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token)
    ):
        raise winerror("OpenProcessToken")
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            raise winerror(f"LookupPrivilegeValueW({name})")
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None):
            raise winerror("AdjustTokenPrivileges")
        if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
            raise RecoveryError(f"This token does not contain {name}.")
    finally:
        close_handle(int(token.value or 0))


def canonical(path: object) -> str:
    """Return a path in the one form every comparison in this package uses."""
    return os.path.normcase(os.path.realpath(str(path)))


def strip_long_path_prefix(path: str) -> str:
    if path.startswith(LONG_PATH_UNC_PREFIX):
        return "\\\\" + path[len(LONG_PATH_UNC_PREFIX) :]
    if path.startswith(LONG_PATH_PREFIX):
        return path[len(LONG_PATH_PREFIX) :]
    return path


class LockedFile:
    """An open handle that denies others write and delete access while it lives.

    The handle has exactly one owner: the file object built from it. Reading, hashing,
    copying, and identity checks all go through this one object, so the bytes that were
    checked are the bytes that get used; the pathname is never reopened.
    """

    def __init__(self, path: object, *, directory: bool = False, open_reparse_point: bool = False,
                 share: int = FILE_SHARE_READ, access: int | None = None) -> None:
        import msvcrt

        flags = FILE_ATTRIBUTE_NORMAL
        if directory:
            flags |= FILE_FLAG_BACKUP_SEMANTICS
        if open_reparse_point:
            flags |= FILE_FLAG_OPEN_REPARSE_POINT
        # Reading a security descriptor needs READ_CONTROL; writing one needs WRITE_DAC,
        # and setting an owner needs WRITE_OWNER, so a repair asks for those explicitly.
        wanted = GENERIC_READ | READ_CONTROL if access is None else access
        ctypes.set_last_error(0)
        raw = kernel32.CreateFileW(
            str(path),
            wanted,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        if not raw or int(raw) == INVALID_HANDLE_VALUE:
            raise winerror(f"CreateFileW({path})")
        self.path = str(path)
        self.directory = directory
        self.access = wanted
        self._closed = False
        self._raw: int | None = None
        self.fileobj = None
        if directory or not wanted & GENERIC_READ:
            # A directory handle cannot back a Python file object, and nothing reads
            # bytes from one: it exists for identity and security checks only. The raw
            # handle is the single owner in this mode.
            self._raw = int(raw)
            return
        try:
            descriptor = msvcrt.open_osfhandle(int(raw), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except OSError:
            close_handle(int(raw))
            raise
        # From here the file object owns the handle; closing it closes the handle once.
        self.fileobj = os.fdopen(descriptor, "rb")

    @property
    def handle(self) -> int:
        import msvcrt

        if self._closed:
            raise RecoveryError(f"The handle for {self.path} is already closed.")
        if self._raw is not None:
            return self._raw
        return int(msvcrt.get_osfhandle(self.fileobj.fileno()))

    def _require_file(self) -> None:
        if self.fileobj is None:
            raise RecoveryError(f"{self.path} was opened as a directory; it has no contents to read.")

    def final_path(self) -> str:
        """The canonical path this handle actually refers to, normcased."""
        buffer = ctypes.create_unicode_buffer(32768)
        ctypes.set_last_error(0)
        length = kernel32.GetFinalPathNameByHandleW(
            wintypes.HANDLE(self.handle), buffer, len(buffer), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        )
        if not length or length >= len(buffer):
            raise winerror(f"GetFinalPathNameByHandleW({self.path})")
        return os.path.normcase(strip_long_path_prefix(buffer.value))

    def attribute_tag(self) -> tuple[int, int]:
        """Return (attributes, reparse tag) read from the handle, not from the name."""
        info = FILE_ATTRIBUTE_TAG_INFORMATION()
        ctypes.set_last_error(0)
        if not kernel32.GetFileInformationByHandleEx(
            wintypes.HANDLE(self.handle), FILE_ATTRIBUTE_TAG_INFO, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise winerror(f"GetFileInformationByHandleEx({self.path})")
        return int(info.FileAttributes), int(info.ReparseTag)

    def is_reparse_point(self) -> bool:
        attributes, tag = self.attribute_tag()
        return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT) or tag != 0

    def size(self) -> int:
        self._require_file()
        return os.fstat(self.fileobj.fileno()).st_size

    def stat(self) -> os.stat_result:
        self._require_file()
        return os.fstat(self.fileobj.fileno())

    def read_chunks(self, chunk: int = 1 << 20):
        """Yield the whole file from the start, through this handle only."""
        self._require_file()
        self.fileobj.seek(0)
        while True:
            data = self.fileobj.read(chunk)
            if not data:
                return
            yield data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._raw is not None:
            close_handle(self._raw)
            self._raw = None
            return
        try:
            self.fileobj.close()
        except OSError:
            pass

    def __enter__(self) -> "LockedFile":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_locked(path: object, **kwargs: object) -> LockedFile:
    """Open `path` so nobody else can write, rename, or delete it while it is open."""
    return LockedFile(path, **kwargs)  # type: ignore[arg-type]


def file_product_version(path: object) -> str:
    """Return a file's ProductVersion resource for display, or an empty string.

    Used only to make an error message more helpful; it never decides a verdict.
    """
    try:
        handle = wintypes.DWORD(0)
        size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(handle))
        if not size:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            return ""
        value = wintypes.LPVOID()
        length = wintypes.UINT()
        if not version.VerQueryValueW(
            buffer, r"\StringFileInfo\040904B0\ProductVersion", ctypes.byref(value), ctypes.byref(length)
        ):
            return ""
        if not value.value or not length.value:
            return ""
        return str(ctypes.wstring_at(value.value, length.value)).strip(chr(0))
    except OSError:
        return ""


def program_files_dir() -> Path:
    """Return the Program Files folder from the Windows shell.

    Environment variables are deliberately not used: a non-elevated caller could set
    %ProgramFiles% before the elevated relaunch and redirect the install into a folder
    it can write.
    """
    folder = GUID.from_string(FOLDERID_PROGRAM_FILES)
    path_pointer = ctypes.c_void_p()
    result = shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, None, ctypes.byref(path_pointer))
    try:
        if result != 0 or not path_pointer.value:
            raise RecoveryError(
                f"SHGetKnownFolderPath(ProgramFiles) failed with HRESULT 0x{result & 0xFFFFFFFF:08X}."
            )
        return Path(ctypes.wstring_at(path_pointer.value))
    finally:
        if path_pointer.value:
            ole32.CoTaskMemFree(path_pointer)
