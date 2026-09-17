"""The Program Files trust boundary: what a protected folder is, and how it is proven.

The scheduled task runs its executable with administrator rights, so that executable
must live where only administrators can change it. This module defines exactly what
that means, reads it back through open handles rather than by pathname, and separates
deviations that may be repaired in place from deviations that must never be, because
whoever caused them could race the repair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Iterable, Protocol

from . import winapi
from .errors import RecoveryError


SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"
SID_CREATOR_OWNER = "S-1-3-0"
SID_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

# Principals that may hold write access inside the install folder. Everything else with
# write access means the folder is not administrator-only.
TRUSTED_WRITERS = frozenset({SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER})
TRUSTED_OWNERS = TRUSTED_WRITERS

# SYSTEM and Administrators full control, Users read and execute, inherited by children,
# and protected so nothing is inherited from Program Files.
PROTECTED_SDDL = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

# The access bits that let a principal change a file, its contents, its name, or its
# permissions. MAXIMUM_ALLOWED counts: it resolves to whatever the principal can get.
WRITE_CLASS_MASK = (
    winapi.FILE_WRITE_DATA
    | winapi.FILE_APPEND_DATA
    | winapi.FILE_WRITE_EA
    | winapi.FILE_WRITE_ATTRIBUTES
    | winapi.FILE_DELETE_CHILD
    | winapi.DELETE
    | winapi.WRITE_DAC
    | winapi.WRITE_OWNER
    | winapi.GENERIC_WRITE_MASK
    | winapi.GENERIC_ALL_MASK
    | winapi.MAXIMUM_ALLOWED
)

WRITE_BIT_NAMES = (
    (winapi.FILE_WRITE_DATA, "write data"),
    (winapi.FILE_APPEND_DATA, "append data"),
    (winapi.FILE_WRITE_EA, "write extended attributes"),
    (winapi.FILE_WRITE_ATTRIBUTES, "write attributes"),
    (winapi.FILE_DELETE_CHILD, "delete child"),
    (winapi.DELETE, "delete"),
    (winapi.WRITE_DAC, "change permissions"),
    (winapi.WRITE_OWNER, "take ownership"),
    (winapi.GENERIC_WRITE_MASK, "generic write"),
    (winapi.GENERIC_ALL_MASK, "generic all"),
    (winapi.MAXIMUM_ALLOWED, "maximum allowed"),
)

# What a folder this installer owns must read back as, exactly.
CANONICAL_ACES = (
    (SID_SYSTEM, winapi.FILE_ALL_ACCESS),
    (SID_ADMINISTRATORS, winapi.FILE_ALL_ACCESS),
    (SID_USERS, winapi.FILE_GENERIC_READ_EXECUTE),
)
CANONICAL_FLAGS = winapi.OBJECT_INHERIT_ACE | winapi.CONTAINER_INHERIT_ACE


@dataclass
class AclReport:
    """What a folder or file reads back as, and how it differs from the canonical form.

    `problems` lists every deviation. `blocking` lists the subset that must not be
    repaired in place, because an untrusted principal could change the folder between
    the check and the repair.
    """

    ok: bool
    owner_sid: str = ""
    problems: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)

    @property
    def repairable(self) -> bool:
        return bool(self.problems) and not self.blocking


def describe_write_bits(mask: int) -> str:
    names = [name for bit, name in WRITE_BIT_NAMES if mask & bit]
    return ", ".join(names) if names else f"0x{mask:08X}"


def _ace_problems(aces: Iterable[winapi.AceEntry], *, inherited: bool) -> tuple[list[str], list[str]]:
    """Compare a DACL with the canonical set. Returns (problems, blocking)."""
    problems: list[str] = []
    blocking: list[str] = []
    observed: list[tuple[str, int]] = []
    for ace in aces:
        if ace.type == winapi.ACCESS_DENIED_ACE_TYPE:
            message = f"ACE {ace.index} denies access to {ace.sid or 'an unreadable SID'}"
            problems.append(message)
            blocking.append(message)
            continue
        if ace.type != winapi.ACCESS_ALLOWED_ACE_TYPE:
            # Callback, conditional, object and unknown ACE types are not interpreted
            # here, so they are never treated as harmless.
            message = f"ACE {ace.index} has unsupported type {ace.type}"
            problems.append(message)
            blocking.append(message)
            continue
        if bool(ace.flags & winapi.INHERITED_ACE) != inherited:
            state = "inherited" if ace.flags & winapi.INHERITED_ACE else "explicit"
            problems.append(f"ACE {ace.index} for {ace.sid} is {state}")
        if ace.sid not in TRUSTED_WRITERS and ace.mask & WRITE_CLASS_MASK:
            message = (
                f"ACE {ace.index} grants {describe_write_bits(ace.mask & WRITE_CLASS_MASK)} to {ace.sid}"
            )
            problems.append(message)
            # An inherit-only CREATOR OWNER entry grants nothing on this folder: it is the
            # template Program Files hands to new children, and the repair replaces the whole
            # list. It stays a problem, so the list is still not canonical and is repaired,
            # but it must not block, or every folder inheriting the Program Files default is
            # refused and the user is told to delete a folder that is not actually unsafe.
            seed_only = ace.sid == SID_CREATOR_OWNER and ace.flags & winapi.INHERIT_ONLY_ACE
            if not seed_only:
                blocking.append(message)
        observed.append((ace.sid, ace.mask))
    if sorted(observed) != sorted(CANONICAL_ACES):
        rendered = ", ".join(f"{sid}:0x{mask:08X}" for sid, mask in observed) or "none"
        problems.append(f"the permission list is not the expected three entries (found {rendered})")
    return problems, blocking


class FileSecurity(Protocol):
    """The operations install.py needs, so tests can supply a fake backend."""

    def verify_owned_dir(self, locked: winapi.LockedFile) -> AclReport: ...

    def verify_child(self, locked: winapi.LockedFile) -> AclReport: ...

    def apply_owned_dir(self, locked: winapi.LockedFile) -> None: ...


def _judge_owned(info, *, inherited: bool) -> AclReport:
    """Judge one security descriptor of an installer owned folder.

    Both the production check, which reads a real handle, and verify_sddl, which reads a
    string, come through here. They were once two copies of these rules, and only the copy
    the tests ran was ever exercised without elevation, so the two could drift apart with
    nothing noticing.
    """
    problems: list[str] = []
    blocking: list[str] = []
    if info.owner not in TRUSTED_OWNERS:
        message = f"the folder is owned by {info.owner or 'an unreadable SID'}"
        problems.append(message)
        blocking.append(message)
    if not info.control & winapi.SE_DACL_PRESENT:
        message = "the folder has no permission list"
        problems.append(message)
        blocking.append(message)
    elif not inherited and not info.control & winapi.SE_DACL_PROTECTED:
        problems.append("the permission list still inherits from Program Files")
    ace_problems, ace_blocking = _ace_problems(info.aces, inherited=inherited)
    problems.extend(ace_problems)
    blocking.extend(ace_blocking)
    return AclReport(not problems, info.owner, problems, blocking)


class WindowsFileSecurity:
    """Reads and writes real Windows security, always through an open handle."""

    def __init__(self) -> None:
        self._privileges_enabled = False

    def verify_owned_dir(self, locked: winapi.LockedFile) -> AclReport:
        """A folder this installer creates: explicit canonical ACEs, protected, trusted owner."""
        return _judge_owned(winapi.read_security(locked.handle), inherited=False)

    def verify_child(self, locked: winapi.LockedFile) -> AclReport:
        """A file or folder inside a protected folder: everything inherited, nothing added."""
        info = winapi.read_security(locked.handle)
        problems: list[str] = []
        blocking: list[str] = []
        if info.owner not in TRUSTED_OWNERS:
            message = f"{locked.path} is owned by {info.owner or 'an unreadable SID'}"
            problems.append(message)
            blocking.append(message)
        if not info.control & winapi.SE_DACL_PRESENT:
            message = f"{locked.path} has no permission list"
            problems.append(message)
            blocking.append(message)
        ace_problems, ace_blocking = _ace_problems(info.aces, inherited=True)
        problems.extend(ace_problems)
        blocking.extend(ace_blocking)
        return AclReport(not problems, info.owner, problems, blocking)

    def apply_owned_dir(self, locked: winapi.LockedFile) -> None:
        """Set the canonical owner and protected permission list on an open folder handle.

        The handle must carry WRITE_DAC and WRITE_OWNER, which open_for_repair requests;
        a read handle fails here with access denied rather than half applying.
        """
        if not self._privileges_enabled:
            # Setting the owner of a folder somebody else owns needs these; without them
            # SetSecurityInfo fails, and the caller stops rather than half repairing.
            for privilege in (winapi.SE_TAKE_OWNERSHIP_NAME, winapi.SE_RESTORE_NAME):
                winapi.enable_privilege(privilege)
            self._privileges_enabled = True
        winapi.apply_security_from_sddl(locked.handle, PROTECTED_SDDL)


def open_for_repair(path: Path, *, directory: bool = True, owner: bool = True) -> winapi.LockedFile:
    """Open a folder or file with exactly the rights a permission repair needs.

    Sharing stays wide here on purpose: this handle exists to rewrite security, not to
    pin bytes, and holding a directory open with a narrow share would block the rename
    that commits an install.
    """
    access = winapi.READ_CONTROL | winapi.WRITE_DAC
    if owner:
        access |= winapi.WRITE_OWNER
    return winapi.open_locked(
        path,
        directory=directory,
        access=access,
        share=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
    )


def verify_sddl(sddl: str, *, inherited: bool = False) -> AclReport:
    """Judge an SDDL string with the very rules used on a real folder.

    This is the same function the production check calls, reached through a string instead
    of a handle, so the tests that drive it exercise the shipped logic rather than a copy.
    """
    return _judge_owned(winapi.read_sddl_security(sddl), inherited=inherited)


def scan_tree(root: Path, security: FileSecurity | None = None) -> list[str]:
    """Report every reason this tree cannot be trusted, before anything is changed.

    Reparse points and hard links are rejected outright: a repair or a delete that
    follows one acts on a target the attacker chose. A folder any untrusted principal
    can write is rejected too, because that principal could create such a link between
    this check and the next step.
    """
    backend = security or WindowsFileSecurity()
    problems: list[str] = []
    pending: list[Path] = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            problems.append(f"{current} could not be read: {exc}")
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                problems.append(f"{path} could not be read: {exc}")
                continue
            if getattr(info, "st_reparse_tag", 0) or info.st_file_attributes & winapi.FILE_ATTRIBUTE_REPARSE_POINT:
                problems.append(f"{path} is a junction, symbolic link, or other reparse point")
                continue
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            try:
                # The link count must come from a real stat: a directory entry carries
                # the data the enumeration returned, where the count is not filled in,
                # so reading it from there would make this check unable to fail.
                links = os.stat(path, follow_symlinks=False).st_nlink
            except OSError as exc:
                problems.append(f"{path} could not be read: {exc}")
                continue
            if links > 1:
                problems.append(f"{path} has more than one name (hard link)")
        problems.extend(_directory_write_problems(current, backend))
    return problems


def _directory_write_problems(folder: Path, backend: FileSecurity) -> list[str]:
    """Blocking problems for one folder: a reparse point, or write access for others."""
    try:
        locked = winapi.open_locked(
            folder,
            directory=True,
            open_reparse_point=True,
            share=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
        )
    except (RecoveryError, OSError) as exc:
        return [f"{folder} could not be opened for inspection: {exc}"]
    try:
        if locked.is_reparse_point():
            return [f"{folder} is a junction, symbolic link, or other reparse point"]
        if winapi.canonical(folder) != locked.final_path():
            return [f"{folder} does not resolve to itself ({locked.final_path()})"]
        report = backend.verify_owned_dir(locked)
        return list(report.blocking)
    finally:
        locked.close()
