"""Closing the error dialog a failed Claude click leaves open, once recovery has proved it stale.

When Claude cannot start because an obsolete Job holds its files, the Windows shell shows
"Another program is currently using this file." Recovery then closes the Job and starts
Claude, but that dialog stays on screen reporting a failure that is no longer true. This
module closes it, and deliberately nothing else:

- only after launch_and_verify has proved Claude is running with no new sharing violation;
- only when Windows logged that exact failure for this package in the last few minutes;
- only a dialog that already existed before Claude was launched, and is still that window;
- only a TaskDialog shown by the Windows shell, titled with this package's own executable.

It presses the dialog's OK button with TDM_CLICK_BUTTON and falls back to WM_CLOSE. It never
signals or terminates the process showing the dialog, and nothing here changes the exit code.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import time
from typing import Protocol

from . import events, winapi
from .package import PackageInfo
from .reporting import Reporter


DIALOG_CLASS = "#32770"
TASK_DIALOG_SURFACE = "DirectUIHWND"
BUTTON_CLASS = "Button"
RECENT_FAILURE_MINUTES = 10
STEP_SECONDS = 2.0
TOTAL_SECONDS = 5.0
POLL_SECONDS = 0.05


class WindowBackend(Protocol):
    """The window operations this module performs, so tests can supply every answer."""

    def top_level_windows(self) -> list[int]: ...

    def class_name(self, hwnd: int) -> str: ...

    def title(self, hwnd: int) -> str: ...

    def owner(self, hwnd: int) -> int: ...

    def visible(self, hwnd: int) -> bool: ...

    def enabled(self, hwnd: int) -> bool: ...

    def exists(self, hwnd: int) -> bool: ...

    def pid(self, hwnd: int) -> int: ...

    def descendants(self, hwnd: int) -> list[int]: ...

    def image_path(self, pid: int) -> str: ...

    def session(self, pid: int) -> int | None: ...

    def current_session(self) -> int | None: ...

    def windows_dir(self) -> Path: ...

    def click_ok(self, hwnd: int) -> bool: ...

    def post_close(self, hwnd: int) -> bool: ...

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class WindowsWindowBackend:
    """The real window manager behind the interface above."""

    def top_level_windows(self) -> list[int]:
        return self._enumerate(None)

    def descendants(self, hwnd: int) -> list[int]:
        return self._enumerate(hwnd)

    def _enumerate(self, parent: int | None) -> list[int]:
        found: list[int] = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def visit(hwnd: int, _lparam: int) -> bool:
            found.append(int(hwnd))
            return True

        if parent is None:
            # EnumWindows also returns FALSE, with no error set, on a desktop that has no top
            # level windows at all. Only a failure Windows actually reports is an error.
            ctypes.set_last_error(0)
            if not winapi.user32.EnumWindows(visit, 0) and ctypes.get_last_error():
                raise winapi.winerror("EnumWindows")
        else:
            # EnumChildWindows walks every descendant, not only direct children, and returns
            # FALSE with no error for a window that has none.
            winapi.user32.EnumChildWindows(parent, visit, 0)
        return found

    def class_name(self, hwnd: int) -> str:
        buffer = ctypes.create_unicode_buffer(256)
        winapi.user32.GetClassNameW(hwnd, buffer, len(buffer))
        return buffer.value

    def title(self, hwnd: int) -> str:
        length = winapi.user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return ""
        buffer = ctypes.create_unicode_buffer(length + 1)
        winapi.user32.GetWindowTextW(hwnd, buffer, length + 1)
        return buffer.value

    def owner(self, hwnd: int) -> int:
        return int(winapi.user32.GetWindow(hwnd, winapi.GW_OWNER) or 0)

    def visible(self, hwnd: int) -> bool:
        return bool(winapi.user32.IsWindowVisible(hwnd))

    def enabled(self, hwnd: int) -> bool:
        return bool(winapi.user32.IsWindowEnabled(hwnd))

    def exists(self, hwnd: int) -> bool:
        return bool(winapi.user32.IsWindow(hwnd))

    def pid(self, hwnd: int) -> int:
        value = wintypes.DWORD()
        winapi.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(value))
        return int(value.value)

    def image_path(self, pid: int) -> str:
        return winapi.process_image_path(pid)

    def session(self, pid: int) -> int | None:
        return winapi.process_session(pid)

    def current_session(self) -> int | None:
        return winapi.process_session(os.getpid())

    def windows_dir(self) -> Path:
        return winapi.windows_dir()

    def click_ok(self, hwnd: int) -> bool:
        result = ctypes.c_size_t()
        sent = winapi.user32.SendMessageTimeoutW(
            hwnd,
            winapi.TDM_CLICK_BUTTON,
            winapi.IDOK,
            0,
            winapi.SMTO_ABORTIFHUNG,
            int(STEP_SECONDS * 1000),
            ctypes.byref(result),
        )
        return bool(sent)

    def post_close(self, hwnd: int) -> bool:
        return bool(winapi.user32.PostMessageW(hwnd, winapi.WM_CLOSE, 0, 0))

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True)
class Candidate:
    """One dialog window mentioning this package, and every reason it may not be closed."""

    hwnd: int
    pid: int
    title: str
    image: str
    reasons: tuple[str, ...] = ()

    @property
    def matches(self) -> bool:
        return not self.reasons


@dataclass(frozen=True)
class Snapshot:
    """The matching dialogs that existed before Claude was launched."""

    windows: tuple[Candidate, ...] = ()
    error: str = ""


@dataclass
class Rules:
    """What a dialog is compared against, resolved once per run."""

    package: PackageInfo
    allowed_owners: frozenset[str]
    session: int | None
    folder_pattern: re.Pattern[str] = field(init=False)

    def __post_init__(self) -> None:
        self.folder_pattern = package_folder_pattern(self.package)


def shell_host_images(backend: WindowBackend) -> frozenset[str]:
    """The two processes allowed to own the dialog, exact paths, from the shell's Windows folder.

    Not "anything under the Windows folder": that includes folders a standard user can write,
    such as Temp and Tasks.
    """
    windows = backend.windows_dir()
    return frozenset(
        os.path.normcase(str(path))
        for path in (windows / "System32" / "sihost.exe", windows / "explorer.exe")
    )


def package_folder_pattern(package: PackageInfo) -> re.Pattern[str]:
    """The install folder name for any version of this package family.

    A package full name is Name_Version_Architecture_ResourceId_PublisherId, and the resource
    id is empty for this package, so the folder reads Name_1.2.3.4_x64__PublisherId. Any
    version is accepted, so an update landing mid incident still matches its own family.
    """
    name, _, publisher = package.package_family_name.partition("_")
    return re.compile(
        rf"^{re.escape(name)}_[0-9]+(?:\.[0-9]+){{3}}_[a-z0-9]+__{re.escape(publisher)}$",
        re.IGNORECASE,
    )


def title_problem(title: str, rules: Rules) -> str | None:
    """Why this title is not the path of this package's own executable, or None."""
    package = rules.package
    if not package.application_executable:
        return "the package manifest names no executable to compare the title with"
    if not package.install_location:
        return "the package has no install location to compare the title with"
    if os.path.normpath(title) != title:
        return "the title is not a plain path"
    root = os.path.normcase(os.path.dirname(os.path.normpath(package.install_location)))
    normalized = os.path.normcase(title)
    if not normalized.startswith(root + os.sep):
        return "the title is not a path in the folder Claude is installed under"
    folder, separator, remainder = normalized[len(root) + 1 :].partition(os.sep)
    if not separator or not rules.folder_pattern.match(folder):
        return "the title does not name a folder of this package"
    if remainder != os.path.normcase(os.path.normpath(package.application_executable)):
        return "the title does not name this package's executable"
    return None


def inspect(hwnd: int, rules: Rules, backend: WindowBackend) -> Candidate:
    """Judge one dialog window against every rule, collecting each reason it fails."""
    title = backend.title(hwnd)
    pid = backend.pid(hwnd)
    image = backend.image_path(pid) if pid else ""
    reasons: list[str] = []
    if backend.class_name(hwnd) != DIALOG_CLASS:
        reasons.append("it is not a dialog window")
    if not backend.visible(hwnd):
        reasons.append("it is not visible")
    if backend.owner(hwnd):
        reasons.append("it belongs to another window")
    if rules.session is None or backend.session(pid) != rules.session:
        reasons.append("it is not in this user's session")
    if not image or os.path.normcase(image) not in rules.allowed_owners:
        reasons.append(f"it is not shown by the Windows shell ({image or 'owner unreadable'})")
    problem = title_problem(title, rules)
    if problem:
        reasons.append(problem)
    classes = [(child, backend.class_name(child)) for child in backend.descendants(hwnd)]
    if not any(name == TASK_DIALOG_SURFACE for _child, name in classes):
        # Without this a property sheet, which shares the class, could receive WM_USER+102,
        # which it reads as a request to remove one of its pages.
        reasons.append("it is not a task dialog")
    if not any(
        name == BUTTON_CLASS and backend.visible(child) and backend.enabled(child) for child, name in classes
    ):
        reasons.append("it has no button to press")
    return Candidate(hwnd, pid, title, image, tuple(reasons))


def resolve_rules(package: PackageInfo, backend: WindowBackend, allowed_owners: frozenset[str] | None) -> Rules:
    owners = allowed_owners if allowed_owners is not None else shell_host_images(backend)
    return Rules(package, frozenset(os.path.normcase(path) for path in owners), backend.current_session())


def candidates(
    package: PackageInfo,
    backend: WindowBackend | None = None,
    allowed_owners: frozenset[str] | None = None,
) -> list[Candidate]:
    """Every visible dialog whose title mentions this package, with its verdict."""
    backend = backend or WindowsWindowBackend()
    rules = resolve_rules(package, backend, allowed_owners)
    _name, _, publisher = package.package_family_name.partition("_")
    marker = publisher.lower()
    found: list[Candidate] = []
    for hwnd in backend.top_level_windows():
        if backend.class_name(hwnd) != DIALOG_CLASS:
            continue
        if not marker or marker not in backend.title(hwnd).lower():
            continue
        found.append(inspect(hwnd, rules, backend))
    return found


def snapshot(
    package: PackageInfo,
    backend: WindowBackend | None = None,
    allowed_owners: frozenset[str] | None = None,
) -> Snapshot:
    """Record the matching dialogs before Claude is launched. Never raises."""
    try:
        matching = tuple(item for item in candidates(package, backend, allowed_owners) if item.matches)
        return Snapshot(matching)
    except Exception as exc:  # noqa: BLE001 - a failed look at the desktop must not stop a launch
        return Snapshot((), str(exc) or type(exc).__name__)


def recent_failure_logged(package: PackageInfo) -> bool:
    """Whether Windows logged this exact sharing violation for this package just now."""
    return bool(events.auto_recovery_events(package, minutes=RECENT_FAILURE_MINUTES))


def dismiss_after_green(
    package: PackageInfo,
    before_launch: Snapshot,
    reporter: Reporter,
    backend: WindowBackend | None = None,
    allowed_owners: frozenset[str] | None = None,
    failure_logged: bool | None = None,
) -> int:
    """Close the stale error dialogs recorded before launch. Returns how many closed.

    Call this only once Claude is proved running (GREEN). It never raises: a dialog that
    cannot be closed is reported and left for the user, and the run's outcome stands.
    """
    try:
        if before_launch.error:
            reporter.emit(
                "NOTE",
                f"The error dialog check could not run before launch ({before_launch.error}), so any "
                "Claude error dialog was left open.",
            )
            return 0
        if not before_launch.windows:
            return 0
        logged = recent_failure_logged(package) if failure_logged is None else failure_logged
        if not logged:
            reporter.emit(
                "NOTE",
                "A Claude error dialog is open, but Windows logged no matching sharing violation in the last "
                f"{RECENT_FAILURE_MINUTES} minutes, so it was left open.",
            )
            return 0
        backend = backend or WindowsWindowBackend()
        rules = resolve_rules(package, backend, allowed_owners)
        deadline = backend.now() + TOTAL_SECONDS
        return sum(_dismiss_one(window, rules, backend, reporter, deadline) for window in before_launch.windows)
    except Exception as exc:  # noqa: BLE001 - dialog handling never changes the outcome
        reporter.emit("NOTE", f"The Claude error dialog could not be closed automatically ({exc}); close it with OK.")
        return 0


def _still_the_same(window: Candidate, rules: Rules, backend: WindowBackend) -> bool:
    if not backend.exists(window.hwnd):
        return False
    current = inspect(window.hwnd, rules, backend)
    return current.matches and current.pid == window.pid and current.title == window.title


def _closed(window: Candidate, backend: WindowBackend) -> bool:
    # A window handle can be reused once its window is gone, so a handle that now belongs to a
    # different process also means the dialog closed.
    return not backend.exists(window.hwnd) or backend.pid(window.hwnd) != window.pid


def _dismiss_one(
    window: Candidate, rules: Rules, backend: WindowBackend, reporter: Reporter, deadline: float
) -> int:
    if not _still_the_same(window, rules, backend):
        if _closed(window, backend):
            return 0
        reporter.emit(
            "NOTE",
            f"The Claude error dialog 0x{window.hwnd:X} changed before it could be closed, so it was left open.",
        )
        return 0
    host = Path(window.image).name or "the Windows shell"
    for step, action in (("TDM_CLICK_BUTTON", backend.click_ok), ("WM_CLOSE", backend.post_close)):
        if backend.now() >= deadline:
            break
        action(window.hwnd)
        step_deadline = min(deadline, backend.now() + STEP_SECONDS)
        while backend.now() < step_deadline and not _closed(window, backend):
            backend.sleep(POLL_SECONDS)
        if _closed(window, backend):
            reporter.emit(
                "DIALOG",
                f"Closed the activation error for {window.title} (shown by {host}, "
                f"hwnd 0x{window.hwnd:X}, by {step}).",
            )
            return 1
        if not _still_the_same(window, rules, backend):
            break
    reporter.emit(
        "NOTE",
        f"The Claude error dialog for {window.title} is still open (hwnd 0x{window.hwnd:X}); close it with OK.",
    )
    return 0
