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


def ps_error(error_id: str, category: str, message: str, *, terminating: bool) -> str:
    """PowerShell, inside an advanced function, that reports an error the way a cmdlet does.

    Cmdlets report some failures by throwing and others by writing an error, and the two
    reach a caller differently, so each stand-in uses the form the real cmdlet was observed
    to use for that failure.
    """
    quoted = message.replace("'", "''")
    report = "ThrowTerminatingError" if terminating else "WriteError"
    return f"""
    $exception = New-Object System.Exception '{quoted}'
    $category = [System.Management.Automation.ErrorCategory]::{category}
    $record = New-Object System.Management.Automation.ErrorRecord -ArgumentList $exception, '{error_id}', $category, $null
    $PSCmdlet.{report}($record)
"""


def failing_cmdlet(
    name: str,
    parameters: tuple[str, ...],
    error_id: str,
    category: str,
    message: str,
    *,
    terminating: bool = False,
) -> str:
    """PowerShell defining a function that stands in for a cmdlet and fails the way it does.

    A function takes precedence over a cmdlet of the same name, so the production script
    runs unchanged against it. The error id and category are the ones the real cmdlet was
    observed to report, which is what the production script decides on.
    """
    declared = ", ".join(f"[string]${parameter}" for parameter in parameters)
    return f"""
function {name} {{
    [CmdletBinding()] param({declared})
{ps_error(error_id, category, message, terminating=terminating)}
}}
"""


def powershell_with(prelude: str):
    """Run every PowerShell query for real, with `prelude` defined before the script."""
    from clauderestart import shell

    real = shell.run_powershell

    def run(script: str, timeout: int = 30) -> str:
        return real(prelude + "\n" + script, timeout)

    return mock.patch.object(shell, "run_powershell", side_effect=run)


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
        status_error: Exception | None = None,
        status_error_after_register: Exception | None = None,
        delete_returncode: int = 0,
    ) -> None:
        self._status = dict(status or {"Installed": False})
        self._xml = xml
        self.status_override = status_override
        self.status_error = status_error
        self.status_error_after_register = status_error_after_register
        self.delete_returncode = delete_returncode
        self.export_error = export_error
        self.register_error = register_error
        self.registered: list[str] = []
        self.deleted = 0
        self.exported = 0

    @property
    def calls(self) -> int:
        return len(self.registered) + self.deleted

    def automation_task_status(self) -> dict[str, object]:
        if self.status_error is not None:
            raise self.status_error
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
        if self.status_error_after_register is not None:
            # Only the lookup that verifies the new registration fails, as a query denied or
            # timed out between the two calls would.
            self.status_error, self.status_error_after_register = self.status_error_after_register, None
        if self.status_override:
            self._status.update(self.status_override)

    def delete_task(self):
        self.deleted += 1
        if self._status.get("Installed") is not True:
            # What schtasks /Delete reports for a task that is not registered.
            return subprocess.CompletedProcess(
                ["schtasks.exe"], 1, stdout="", stderr="ERROR: The system cannot find the file specified."
            )
        if self.delete_returncode != 0:
            return subprocess.CompletedProcess(
                ["schtasks.exe"], self.delete_returncode, stdout="", stderr="ERROR: Access is denied."
            )
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
