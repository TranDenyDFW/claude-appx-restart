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


if __name__ == "__main__":
    unittest.main()
