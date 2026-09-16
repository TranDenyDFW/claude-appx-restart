"""A real task survives being exported and registered again.

The rollback path restores the previous task from exported XML. If the export loses a
setting, the restore quietly installs a weaker task: one that will not start on battery, or
that Windows may disable, and the user is told the previous task was put back unchanged.
Nothing else in the suite exercises the Task Scheduler itself, so every other test would
stay green while that happened.

Registering a task needs elevation, so this runs on the elevated continuous integration
runner and skips on a normal desktop.
"""

from __future__ import annotations

from pathlib import Path
import secrets
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import shell, task, winapi  # noqa: E402


@unittest.skipUnless(
    sys.platform == "win32" and winapi.is_admin(), "registering a scheduled task needs elevation"
)
class TaskRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        winapi.configure()
        self.name = f"ClaudeRestart-Test-{secrets.token_hex(4)}"
        # Registered before anything else, so an assertion failure still removes the task.
        self.addCleanup(task.delete_task, self.name)
        self.executable = Path(sys.executable).resolve()
        self.definition = task.build_task_xml(
            self.executable,
            task.TASK_ARGUMENTS,
            self.current_sid(),
            self.executable.parent,
            task_name=self.name,
        )

    def current_sid(self) -> str:
        sid = shell.run_powershell(
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        ).strip()
        self.assertTrue(sid.startswith("S-1-"), sid)
        return sid

    def test_a_registered_task_survives_an_export_and_a_restore(self) -> None:
        task.register_task_xml(self.definition, name=self.name)
        status = task.automation_task_status(self.name)
        self.assertIs(status.get("Installed"), True, status)
        self.assertEqual(
            task.verify_registered_task(status, task.TASK_ARGUMENTS, self.executable), [], status
        )

        exported = task.export_task_xml(self.name)
        self.assertTrue(exported.strip(), "the export must not be empty")

        task.delete_task(self.name)
        self.assertIsNot(task.automation_task_status(self.name).get("Installed"), True)

        # This is the rollback: the previous definition, put back from its export alone.
        task.register_task_xml(exported, name=self.name)
        restored = task.automation_task_status(self.name)
        self.assertIs(restored.get("Installed"), True, restored)
        self.assertEqual(
            task.verify_registered_task(restored, task.TASK_ARGUMENTS, self.executable), [], restored
        )

    def test_an_absent_task_reports_itself_absent(self) -> None:
        # The installer decides whether there was a task from this, never from an export.
        self.assertIsNot(task.automation_task_status(self.name).get("Installed"), True)


if __name__ == "__main__":
    unittest.main()
