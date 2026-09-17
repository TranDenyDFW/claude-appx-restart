"""The registered task definition and the launcher it runs."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import events, payload, task  # noqa: E402


TASK_NS = {"t": task.TASK_XML_NAMESPACE}


class TaskXmlTests(unittest.TestCase):
    def build(self) -> ET.Element:
        xml_text = task.build_task_xml(
            Path(r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe"),
            task.TASK_ARGUMENTS,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            Path(r"C:\Tools\ClaudeRestart"),
        )
        self.assertTrue(xml_text.startswith('<?xml version="1.0" encoding="UTF-16"?>'))
        self.assertNotIn("1.52386", xml_text)
        return ET.fromstring(xml_text.encode("utf-16"))

    def test_task_xml_sets_the_reviewed_settings(self) -> None:
        settings = self.build().find("t:Settings", TASK_NS)
        self.assertIsNotNone(settings)
        for tag, expected in task.TASK_SETTINGS:
            self.assertEqual(settings.findtext(f"t:{tag}", namespaces=TASK_NS), expected, tag)
        self.assertEqual(settings.findtext("t:DisallowStartIfOnBatteries", namespaces=TASK_NS), "false")
        self.assertEqual(settings.findtext("t:StopIfGoingOnBatteries", namespaces=TASK_NS), "false")
        self.assertEqual(settings.findtext("t:MultipleInstancesPolicy", namespaces=TASK_NS), "IgnoreNew")
        self.assertEqual(settings.findtext("t:ExecutionTimeLimit", namespaces=TASK_NS), "PT5M")

    def test_task_xml_principal_and_action(self) -> None:
        built = self.build()
        principal = built.find("t:Principals/t:Principal", TASK_NS)
        self.assertEqual(
            principal.findtext("t:UserId", namespaces=TASK_NS),
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        )
        self.assertEqual(principal.findtext("t:LogonType", namespaces=TASK_NS), "InteractiveToken")
        self.assertEqual(principal.findtext("t:RunLevel", namespaces=TASK_NS), "HighestAvailable")
        exec_node = built.find("t:Actions/t:Exec", TASK_NS)
        self.assertEqual(
            exec_node.findtext("t:Command", namespaces=TASK_NS),
            r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe",
        )
        self.assertEqual(exec_node.findtext("t:Arguments", namespaces=TASK_NS), task.TASK_ARGUMENTS)
        self.assertEqual(
            exec_node.findtext("t:WorkingDirectory", namespaces=TASK_NS), r"C:\Tools\ClaudeRestart"
        )

    def test_task_xml_subscription_is_the_stable_xpath(self) -> None:
        trigger = self.build().find("t:Triggers/t:EventTrigger", TASK_NS)
        self.assertEqual(trigger.findtext("t:Enabled", namespaces=TASK_NS), "true")
        subscription = trigger.findtext("t:Subscription", namespaces=TASK_NS)
        self.assertIn(events.AUTO_RECOVERY_XPATH, subscription)
        self.assertIn(events.APPMODEL_LOG, subscription)
        query = ET.fromstring(subscription)  # the escaped QueryList must itself be well-formed
        self.assertEqual(query.tag, "QueryList")
        self.assertEqual(query.find("Query/Select").text, events.AUTO_RECOVERY_XPATH)


class TaskActionTests(unittest.TestCase):
    def test_task_action_quotes_executable_for_exe_and_source(self) -> None:
        self.assertEqual(
            task.build_task_action(
                Path(r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe"), task.TASK_ARGUMENTS
            ),
            '"C:\\Tools\\ClaudeRestart\\ClaudeRestart-quiet.exe" --event-triggered --yes --wait 30',
        )
        self.assertEqual(
            task.build_task_action(
                Path(r"C:\Program Files\Python\pythonw.exe"),
                '"C:\\Users\\Example User\\Claude Restart\\claude_restart.py" --event-triggered --yes --wait 30',
            ),
            '"C:\\Program Files\\Python\\pythonw.exe" '
            '"C:\\Users\\Example User\\Claude Restart\\claude_restart.py" '
            "--event-triggered --yes --wait 30",
        )


class LauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / payload.CONSOLE_EXE_NAME
        self.exe.write_bytes(b"")

    def test_task_launcher_frozen_prefers_the_quiet_twin(self) -> None:
        with support.frozen_at(self.exe):
            executable, arguments = task.task_launcher()
        self.assertEqual(executable, self.exe)
        self.assertEqual(arguments, task.TASK_ARGUMENTS)

        twin = self.root / payload.QUIET_EXE_NAME
        twin.write_bytes(b"")
        with support.frozen_at(self.exe):
            executable, arguments = task.task_launcher()
        self.assertEqual(executable, twin)
        self.assertEqual(arguments, task.TASK_ARGUMENTS)
        self.assertEqual(
            task.build_task_action(executable, arguments),
            f'"{twin}" --event-triggered --yes --wait 30',
        )

    @unittest.skipUnless(sys.platform == "win32", "task interpreter selection is Windows-only")
    def test_task_launcher_from_source_uses_python_and_the_entry_script(self) -> None:
        executable, arguments = task.task_launcher()
        self.assertIn(executable.name.lower(), ("pythonw.exe", "python.exe"))
        self.assertTrue(arguments.startswith('"'))
        self.assertIn("claude_restart.py", arguments)
        self.assertNotIn("clauderestart" + chr(92), arguments)  # never a module inside the package
        self.assertTrue(arguments.endswith(task.TASK_ARGUMENTS))


class RegisteredTaskVerificationTests(unittest.TestCase):
    """Whether the task Windows actually holds is the task that was asked for.

    No test named verify_registered_task before, so the comparison that ties the registered
    action to the executable just installed could be deleted with the whole suite still green.
    That comparison is the only thing standing between an upgrade and a task still running the
    previous version.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.executable = self.folder / payload.QUIET_EXE_NAME
        self.executable.write_bytes(b"installed twin")

    def status(self, **overrides: object) -> dict[str, object]:
        subscription = (
            "<QueryList><Query><Select>*[EventData[Data="
            f"'{task.AUTO_RECOVERY_APPLICATION}' and Data='{events.SHARE_VIOLATION_DECIMAL}']]"
            "</Select></Query></QueryList>"
        )
        status: dict[str, object] = {
            "Installed": True,
            "MultipleInstances": "IgnoreNew",
            "LogonType": "InteractiveToken",
            "RunLevel": "HighestAvailable",
            "ExecutionTimeLimit": "PT5M",
            "DisallowStartIfOnBatteries": False,
            "StopIfGoingOnBatteries": False,
            "Subscription": subscription,
            "Arguments": task.TASK_ARGUMENTS,
            "Execute": f'"{self.executable}"',
        }
        status.update(overrides)
        return status

    def verify(self, **overrides: object) -> list[str]:
        return task.verify_registered_task(self.status(**overrides), task.TASK_ARGUMENTS, self.executable)

    def test_a_correctly_registered_task_has_no_problems(self) -> None:
        self.assertEqual(self.verify(), [])

    def test_a_task_running_another_executable_is_rejected(self) -> None:
        other = self.folder / "somewhere-else.exe"
        other.write_bytes(b"another build")
        problems = self.verify(Execute=f'"{other}"')
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("the task runs", problems[0])
        self.assertIn(other.name, problems[0])

    def test_an_unquoted_action_resolves_to_the_same_file(self) -> None:
        self.assertEqual(
            task.verify_registered_task(
                self.status(Execute=str(self.executable)), task.TASK_ARGUMENTS, self.executable
            ),
            [],
        )

    def test_a_task_that_is_not_registered_reports_only_that(self) -> None:
        self.assertEqual(self.verify(Installed=False), ["the task is not registered"])

    def test_every_wrong_setting_is_named(self) -> None:
        cases = {
            "MultipleInstances": ("Parallel", "MultipleInstances"),
            "LogonType": ("Password", "LogonType"),
            "RunLevel": ("Limited", "RunLevel"),
            "ExecutionTimeLimit": ("PT72H", "ExecutionTimeLimit"),
            "DisallowStartIfOnBatteries": (True, "battery"),
            "StopIfGoingOnBatteries": (True, "unplugged"),
            "Arguments": ("--yes", "arguments"),
        }
        for field, (value, expected) in cases.items():
            with self.subTest(field=field):
                problems = self.verify(**{field: value})
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(expected, problems[0])

    def test_a_subscription_that_does_not_name_the_failure_is_rejected(self) -> None:
        self.assertIn("no event subscription", self.verify(Subscription="")[0])
        self.assertIn("does not name the Claude application", self.verify(Subscription="<QueryList/>")[0])
        naming_app = f"<QueryList>{task.AUTO_RECOVERY_APPLICATION}</QueryList>"
        self.assertIn("does not name the sharing violation", self.verify(Subscription=naming_app)[0])


class TaskQueryTests(unittest.TestCase):
    """Absent and unreadable are different answers, and only absent may read as not installed."""

    @unittest.skipUnless(sys.platform == "win32", "Task Scheduler is Windows only")
    def test_a_task_that_does_not_exist_is_reported_absent_not_as_an_error(self) -> None:
        # Real Task Scheduler, read only: a lookup that finds nothing must still say "absent",
        # so treating other failures as errors does not turn a clean machine into an error.
        import secrets

        status = task.automation_task_status(f"ClaudeRestart-Absent-{secrets.token_hex(8)}")
        self.assertEqual(status, {"Installed": False})

    def test_a_query_that_fails_raises_instead_of_reporting_absent(self) -> None:
        from unittest import mock

        from clauderestart.errors import RecoveryError

        failure = RecoveryError("PowerShell query failed (1): Task Scheduler could not be queried: Access denied")
        with mock.patch.object(task.shell, "run_powershell", side_effect=failure):
            with self.assertRaises(RecoveryError) as stop:
                task.automation_task_status()
        self.assertIn("could not be queried", str(stop.exception))

    def test_only_a_not_found_lookup_is_mapped_to_absent(self) -> None:
        # The script itself decides; the real failure it guards against, a denied query under a
        # restricted token, cannot be produced in a unit test and was verified on a real machine.
        from unittest import mock

        with mock.patch.object(task.shell, "run_powershell", return_value='{"Installed":false}') as query:
            task.automation_task_status()
        script = query.call_args.args[0]
        self.assertIn("-ErrorAction Stop", script)
        self.assertIn("'ObjectNotFound'", script)
        self.assertNotIn("SilentlyContinue\nif (-not $task)", script)


if __name__ == "__main__":
    unittest.main()
