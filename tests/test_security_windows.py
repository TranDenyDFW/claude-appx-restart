"""The protected permission list applied to a real folder, and what it actually denies.

The verdict tests judge descriptors. These tests apply the real list to a real folder
and then ask Windows itself, through AccessCheck with a standard-user token, whether
writing, renaming and deleting are refused. A known-bad control proves the check can
fail: the same question against a weakened list must report write as granted.

Every test restores a permissive list before the temporary folder is removed, and none
of them needs elevation: the owner of a folder keeps the right to change its list.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import security, winapi  # noqa: E402


TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_IMPERSONATE = 0x0004
SECURITY_IMPERSONATION = 2
TOKEN_IMPERSONATION = 2
DISABLE_MAX_PRIVILEGE = 0x1
OWNER_SECURITY_INFORMATION = winapi.OWNER_SECURITY_INFORMATION
DACL_SECURITY_INFORMATION = winapi.DACL_SECURITY_INFORMATION
GROUP_SECURITY_INFORMATION = winapi.GROUP_SECURITY_INFORMATION


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]


class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Control", wintypes.DWORD),
        ("Privilege", winapi.LUID_AND_ATTRIBUTES * 1),
    ]


def _configure_test_apis() -> None:
    advapi32 = winapi.advapi32
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.DuplicateTokenEx.restype = wintypes.BOOL
    advapi32.AccessCheck.argtypes = [
        ctypes.c_void_p,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(GENERIC_MAPPING),
        ctypes.POINTER(PRIVILEGE_SET),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.AccessCheck.restype = wintypes.BOOL
    advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL
    advapi32.FreeSid.argtypes = [ctypes.c_void_p]
    advapi32.FreeSid.restype = ctypes.c_void_p
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL


def standard_user_token() -> int:
    """A token like a normal user's: the Administrators group disabled.

    On a filtered (non-elevated) token that group is already deny only, so this returns
    an equivalent token in both an elevated CI run and a normal desktop run.
    """
    advapi32 = winapi.advapi32
    kernel32 = winapi.kernel32
    process_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, ctypes.byref(process_token)
    ):
        raise AssertionError("OpenProcessToken failed")
    administrators = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(security.SID_ADMINISTRATORS, ctypes.byref(administrators)):
        raise AssertionError("ConvertStringSidToSidW failed")
    disable = (SID_AND_ATTRIBUTES * 1)()
    disable[0].Sid = administrators
    disable[0].Attributes = 0
    restricted = wintypes.HANDLE()
    ok = advapi32.CreateRestrictedToken(
        process_token,
        DISABLE_MAX_PRIVILEGE,
        1,
        ctypes.cast(disable, ctypes.c_void_p),
        0,
        None,
        0,
        None,
        ctypes.byref(restricted),
    )
    winapi.close_handle(int(process_token.value or 0))
    if not ok:
        raise AssertionError("CreateRestrictedToken failed")
    impersonation = wintypes.HANDLE()
    ok = advapi32.DuplicateTokenEx(
        restricted,
        TOKEN_QUERY | TOKEN_IMPERSONATE,
        None,
        SECURITY_IMPERSONATION,
        TOKEN_IMPERSONATION,
        ctypes.byref(impersonation),
    )
    winapi.close_handle(int(restricted.value or 0))
    if not ok:
        raise AssertionError("DuplicateTokenEx failed")
    return int(impersonation.value or 0)


def granted(path: Path, token: int, desired: int) -> bool:
    """Ask Windows whether `token` gets `desired` access to `path`."""
    advapi32 = winapi.advapi32
    descriptor = ctypes.c_void_p()
    size = wintypes.DWORD()
    advapi32.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    advapi32.GetFileSecurityW(str(path), information, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetFileSecurityW(str(path), information, buffer, size.value, ctypes.byref(size)):
        raise AssertionError("GetFileSecurityW failed")
    descriptor = ctypes.cast(buffer, ctypes.c_void_p)
    mapping = GENERIC_MAPPING(
        winapi.FILE_GENERIC_READ_EXECUTE,
        winapi.FILE_ALL_ACCESS,
        winapi.FILE_GENERIC_READ_EXECUTE,
        winapi.FILE_ALL_ACCESS,
    )
    privileges = PRIVILEGE_SET()
    privileges_length = wintypes.DWORD(ctypes.sizeof(privileges))
    access = wintypes.DWORD()
    result = wintypes.BOOL()
    if not advapi32.AccessCheck(
        descriptor,
        wintypes.HANDLE(token),
        desired,
        ctypes.byref(mapping),
        ctypes.byref(privileges),
        ctypes.byref(privileges_length),
        ctypes.byref(access),
        ctypes.byref(result),
    ):
        raise AssertionError(f"AccessCheck failed: {ctypes.WinError(ctypes.get_last_error())}")
    return bool(result.value)


@unittest.skipUnless(sys.platform == "win32", "Windows security only")
class ProtectedFolderTests(unittest.TestCase):
    # The owner of a folder can always rewrite its permission list, so these run
    # unelevated; only the owner itself cannot be changed without a privilege.
    DACL_ONLY = security.PROTECTED_SDDL.split("D:", 1)[1]

    def setUp(self) -> None:
        winapi.configure()
        _configure_test_apis()
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name).resolve()
        self.target = self.folder / "ClaudeRestart-quiet.exe"
        self.target.write_bytes(b"installed executable")
        self.token = standard_user_token()
        self.addCleanup(winapi.close_handle, self.token)
        # Registered before anything is applied, so the folder is always removable.
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.restore_permissive)

    def restore_permissive(self) -> None:
        for path in (self.target, self.folder):
            try:
                locked = security.open_for_repair(path, directory=path.is_dir(), owner=False)
            except Exception:  # noqa: BLE001 - cleanup must not mask a test failure
                continue
            try:
                winapi.apply_security_from_sddl(locked.handle, "D:(A;OICI;FA;;;WD)", owner=False)
            except Exception:  # noqa: BLE001
                pass
            finally:
                locked.close()

    def apply_protected(self, sddl_dacl: str | None = None) -> None:
        locked = security.open_for_repair(self.folder, owner=False)
        try:
            winapi.apply_security_from_sddl(locked.handle, "D:" + (sddl_dacl or self.DACL_ONLY), owner=False)
        finally:
            locked.close()

    def test_the_applied_list_reads_back_as_the_canonical_three_entries(self) -> None:
        self.apply_protected()
        locked = winapi.open_locked(
            self.folder,
            directory=True,
            share=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
        )
        try:
            info = winapi.read_security(locked.handle)
        finally:
            locked.close()
        self.assertTrue(info.control & winapi.SE_DACL_PROTECTED, "the list must not inherit")
        observed = sorted((ace.sid, ace.mask) for ace in info.aces)
        self.assertEqual(observed, sorted(security.CANONICAL_ACES))

    def test_a_standard_user_is_denied_write_rename_and_delete(self) -> None:
        self.apply_protected()
        for desired, name in (
            (winapi.FILE_WRITE_DATA, "write data"),
            (winapi.FILE_APPEND_DATA, "append data"),
            (winapi.DELETE, "delete"),
            (winapi.FILE_WRITE_ATTRIBUTES, "write attributes"),
        ):
            with self.subTest(right=name):
                self.assertFalse(granted(self.target, self.token, desired), f"{name} must be denied")
        self.assertFalse(granted(self.folder, self.token, winapi.FILE_DELETE_CHILD), "delete child must be denied")
        self.assertTrue(
            granted(self.target, self.token, winapi.FILE_GENERIC_READ_EXECUTE),
            "reading and running the installed file must still work",
        )

    @unittest.skipUnless(sys.platform == "win32" and winapi.is_admin(), "setting an owner needs elevation")
    def test_with_the_canonical_owner_even_permission_changes_are_denied(self) -> None:
        # An object's owner always keeps read control and the right to rewrite the list,
        # so the owner must be Administrators; that is what apply_owned_dir sets, and it
        # is the only way these two rights can be denied to a standard user.
        backend = security.WindowsFileSecurity()
        locked = security.open_for_repair(self.folder)
        try:
            backend.apply_owned_dir(locked)
            report = backend.verify_owned_dir(locked)
        finally:
            locked.close()
        self.assertTrue(report.ok, report.problems)
        self.assertEqual(report.owner_sid, security.SID_ADMINISTRATORS)
        for desired, name in (
            (winapi.WRITE_DAC, "change permissions"),
            (winapi.WRITE_OWNER, "take ownership"),
            (winapi.FILE_WRITE_DATA, "write data"),
            (winapi.DELETE, "delete"),
        ):
            with self.subTest(right=name):
                self.assertFalse(granted(self.folder, self.token, desired), f"{name} must be denied")

    def test_the_denial_check_can_fail(self) -> None:
        # Known-bad control: grant Users full control and the same question must say yes.
        self.apply_protected("P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
        self.assertTrue(
            granted(self.target, self.token, winapi.FILE_WRITE_DATA),
            "the check reports write as granted when the list actually allows it",
        )


if __name__ == "__main__":
    unittest.main()
