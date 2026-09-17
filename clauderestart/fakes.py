"""A scripted Job inspector, used by the self-check and by the tests.

This ships inside the executable on purpose: --self-check runs the race fixtures, so
the same driver that repairs a real incident is exercised in every build and on every
machine, rather than a second copy written only for tests.
"""

from __future__ import annotations

import ctypes

from . import winapi
from .recovery import ProcessInfo


# A blob the size of the real limits structure, so callers that parse it can.
EMPTY_LIMITS = bytes(ctypes.sizeof(winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION))


class FakeJobInspector:
    """Answers Job queries from a script, and counts everything it was asked to do.

    `snapshots` is the sequence of member lists that successive pids() calls return;
    the last one repeats once the script runs out. `info` maps a PID to the
    ProcessInfo values returned by successive process_info() calls, so a fixture can
    make a PID look reused by changing its creation time between calls.
    """

    def __init__(
        self,
        snapshots,
        *,
        session: int | None = 1,
        info: dict[int, object] | None = None,
        freeze_available: bool = True,
        set_limit_error: Exception | None = None,
        terminate_error: Exception | None = None,
        saved_limits: bytes | None = None,
    ) -> None:
        self._snapshots = [list(snapshot) for snapshot in snapshots] or [[]]
        self._index = 0
        self._session = session
        self._info = dict(info or {})
        self._freeze_available = freeze_available
        self._set_limit_error = set_limit_error
        self._terminate_error = terminate_error
        self._saved_limits = EMPTY_LIMITS if saved_limits is None else saved_limits
        self.pid_calls = 0
        self.duplicate_calls = 0
        self.set_limit_calls: list[int] = []
        self.restore_calls: list[bytes] = []
        self.terminate_calls = 0
        self.closed: list[int] = []

    def pids(self, job: object) -> list[int]:
        snapshot = self._snapshots[min(self._index, len(self._snapshots) - 1)]
        self._index += 1
        self.pid_calls += 1
        return sorted(snapshot)

    def process_info(self, pid: int) -> ProcessInfo:
        entry = self._info.get(pid)
        if isinstance(entry, list):
            value = entry.pop(0) if len(entry) > 1 else entry[0]
            return value
        if entry is not None:
            return entry
        return ProcessInfo(pid, "claude.exe", r"C:\Program Files\WindowsApps\Claude\claude.exe", "", self._session, 5)

    def current_session(self) -> int | None:
        return self._session

    def duplicate_for_freeze(self, job: object) -> int:
        self.duplicate_calls += 1
        if not self._freeze_available:
            raise OSError(5, "Access is denied")
        return 0xF00D

    def query_limits(self, handle: int) -> bytes:
        return self._saved_limits

    def set_active_process_limit(self, handle: int, count: int) -> None:
        self.set_limit_calls.append(count)
        if self._set_limit_error is not None:
            raise self._set_limit_error

    def restore_limits(self, handle: int, saved: bytes) -> None:
        self.restore_calls.append(saved)

    def accounting(self, handle: int) -> int:
        return len(self.pids(None))

    def granted_access(self, handle: int) -> int:
        return 0

    def terminate(self, job: object) -> None:
        self.terminate_calls += 1
        if self._terminate_error is not None:
            raise self._terminate_error

    def close(self, handle: int) -> None:
        self.closed.append(handle)
