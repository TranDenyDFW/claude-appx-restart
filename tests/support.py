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
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clauderestart import winapi  # noqa: E402
from clauderestart.errors import RecoveryError  # noqa: E402
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
    """A stand-in Task Scheduler that answers from the definition it was given.

    Registering makes the reported status reflect the XML that was registered, so the
    verification the installer performs is real work rather than a rubber stamp; a test
    forces a mismatch by passing status_override.
    """

    def __init__(
        self,
        *,
        status: dict[str, object] | None = None,
        xml: str | None = None,
        status_override: dict[str, object] | None = None,
        export_error: Exception | None = None,
        register_error: Exception | None = None,
    ) -> None:
        self._status = dict(status or {"Installed": False})
        self._xml = xml
        self.status_override = status_override
        self.export_error = export_error
        self.register_error = register_error
        self.registered: list[str] = []
        self.deleted = 0
        self.exported = 0

    @property
    def calls(self) -> int:
        return len(self.registered) + self.deleted

    def automation_task_status(self) -> dict[str, object]:
        return dict(self._status)

    def export_task_xml(self) -> str:
        if self.export_error is not None:
            raise self.export_error
        self.exported += 1
        if not self._xml:
            raise RecoveryError("Could not capture the existing task for rollback: the export was empty.")
        return self._xml

    def register_task_xml(self, xml_text: str) -> None:
        self.registered.append(xml_text)
        if self.register_error is not None:
            error, self.register_error = self.register_error, None
            raise error
        self._xml = xml_text
        self._status = self.status_from_xml(xml_text)
        if self.status_override:
            self._status.update(self.status_override)

    def delete_task(self):
        self.deleted += 1
        self._status = {"Installed": False}
        return subprocess.CompletedProcess(["schtasks.exe"], 0, stdout="", stderr="")

    @staticmethod
    def status_from_xml(xml_text: str) -> dict[str, object]:
        """Report what the registered definition actually says."""
        body = xml_text.split("?>", 1)[-1] if xml_text.lstrip().startswith("<?xml") else xml_text
        root = ET.fromstring(body)
        namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

        def text(path: str, default: str = "") -> str:
            return root.findtext(path, default=default, namespaces=namespace)

        return {
            "Installed": True,
            "State": "Ready",
            "MultipleInstances": text("t:Settings/t:MultipleInstancesPolicy"),
            "LogonType": text("t:Principals/t:Principal/t:LogonType"),
            "RunLevel": text("t:Principals/t:Principal/t:RunLevel"),
            "Subscription": text("t:Triggers/t:EventTrigger/t:Subscription"),
            "Execute": text("t:Actions/t:Exec/t:Command"),
            "Arguments": text("t:Actions/t:Exec/t:Arguments"),
            "DisallowStartIfOnBatteries": text("t:Settings/t:DisallowStartIfOnBatteries") == "true",
            "StopIfGoingOnBatteries": text("t:Settings/t:StopIfGoingOnBatteries") == "true",
            "ExecutionTimeLimit": text("t:Settings/t:ExecutionTimeLimit"),
            "Priority": int(text("t:Settings/t:Priority", "5") or 5),
            "Description": "",
            "LastRunTime": "",
            "LastTaskResult": 0,
        }
