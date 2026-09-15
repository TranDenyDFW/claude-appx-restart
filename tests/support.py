"""Shared test helpers.

Importing this module puts the repository root on sys.path, so every test file can
start with `import support` and then import the clauderestart package.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
from pathlib import Path
import subprocess
import sys
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clauderestart import winapi  # noqa: E402
from clauderestart.security import AclReport  # noqa: E402


def frozen_at(executable: Path) -> ExitStack:
    """Pretend to run as the frozen executable at `executable`.

    Frozen mode is read in exactly one place, winapi.is_frozen(), so this patches
    that function and sys.executable and nothing else.
    """
    stack = ExitStack()
    stack.enter_context(mock.patch.object(winapi, "is_frozen", return_value=True))
    stack.enter_context(mock.patch.object(sys, "executable", str(executable)))
    return stack


def tree_hash(root: Path) -> dict[str, str]:
    """Map every file under `root` to its digest, for proving a tree did not change."""
    digests: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


class FakeFileSecurity:
    """A security backend that records calls and answers from a script.

    Real permission checks are covered by tests/test_security.py and
    tests/test_security_windows.py; install tests use this to drive the branches that
    depend on a verdict without needing elevation.
    """

    def __init__(
        self,
        *,
        verdicts: list[AclReport] | None = None,
        child_verdict: AclReport | None = None,
        apply_error: Exception | None = None,
    ) -> None:
        self.verdicts = list(verdicts or [])
        self.child_verdict = child_verdict
        self.apply_error = apply_error
        self.applied: list[str] = []
        self.verified: list[str] = []

    def _next(self) -> AclReport:
        if self.verdicts:
            return self.verdicts.pop(0)
        return AclReport(True, "S-1-5-32-544", [], [])

    def verify_owned_dir(self, locked) -> AclReport:
        self.verified.append(str(locked.path))
        return self._next()

    def verify_child(self, locked) -> AclReport:
        self.verified.append(str(locked.path))
        return self.child_verdict or AclReport(True, "S-1-5-32-544", [], [])

    def apply_owned_dir(self, locked) -> None:
        self.applied.append(str(locked.path))
        if self.apply_error is not None:
            raise self.apply_error


class FakeTaskBackend:
    """Records every scheduled-task call so a test can prove none was made."""

    def __init__(self, *, status: dict[str, object] | None = None, xml: str | None = None) -> None:
        self.status = status or {"Installed": False}
        self.xml = xml
        self.registered: list[str] = []
        self.deleted = 0
        self.exported = 0
        self.register_error: Exception | None = None

    def automation_task_status(self) -> dict[str, object]:
        return dict(self.status)

    def export_task_xml(self) -> str | None:
        self.exported += 1
        return self.xml

    def register_task_xml(self, xml_text: str) -> None:
        self.registered.append(xml_text)
        if self.register_error is not None:
            error, self.register_error = self.register_error, None
            raise error

    def delete_task(self):
        self.deleted += 1
        return subprocess.CompletedProcess(["schtasks.exe"], 0, stdout="", stderr="")
