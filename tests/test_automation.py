from __future__ import annotations

from contextlib import ExitStack
import ctypes
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import claude_restart as app  # noqa: E402


ERROR_EVENT = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-AppModel-Runtime" />
    <EventID>208</EventID>
    <EventRecordID>233166</EventRecordID>
  </System>
  <EventData>
    <Data Name="PackageName">Claude_9.99999.1.0_x64__pzs8sxrjxfjjc</Data>
    <Data Name="ImageName">Claude.exe</Data>
    <Data Name="ApplicationName">Claude_pzs8sxrjxfjjc!Claude</Data>
    <Data Name="ErrorCode">2147942432</Data>
    <Data Name="Message">[LaunchProcess]</Data>
  </EventData>
</Event>
"""

TASK_NS = {"t": app.TASK_XML_NAMESPACE}


def changed_event(*, event_id: int = 208, application: str = "Claude_pzs8sxrjxfjjc!Claude", error: str = "2147942432") -> str:
    return (
        ERROR_EVENT.replace("<EventID>208</EventID>", f"<EventID>{event_id}</EventID>")
        .replace("Claude_pzs8sxrjxfjjc!Claude", application)
        .replace("<Data Name=\"ErrorCode\">2147942432</Data>", f"<Data Name=\"ErrorCode\">{error}</Data>")
    )


class EventAutomationTests(unittest.TestCase):
    def test_exact_structured_failure_is_selected_across_package_versions(self) -> None:
        self.assertTrue(app.is_auto_recovery_event(ERROR_EVENT))

    def test_nearby_events_are_rejected(self) -> None:
        self.assertFalse(app.is_auto_recovery_event(changed_event(event_id=215)))
        self.assertFalse(app.is_auto_recovery_event(changed_event(application="Other.App!Main")))
        self.assertFalse(app.is_auto_recovery_event(changed_event(error="5")))

    def test_scheduler_xpath_uses_stable_structured_fields_not_package_version(self) -> None:
        self.assertIn("EventID=208", app.AUTO_RECOVERY_XPATH)
        self.assertIn("Claude_pzs8sxrjxfjjc!Claude", app.AUTO_RECOVERY_XPATH)
        self.assertIn("2147942432", app.AUTO_RECOVERY_XPATH)
        self.assertNotIn("1.52386", app.AUTO_RECOVERY_XPATH)

    def test_task_action_quotes_executable_for_exe_and_source(self) -> None:
        self.assertEqual(
            app.build_task_action(Path(r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe"), app.TASK_ARGUMENTS),
            '"C:\\Tools\\ClaudeRestart\\ClaudeRestart-quiet.exe" --event-triggered --yes --wait 30',
        )
        self.assertEqual(
            app.build_task_action(
                Path(r"C:\Program Files\Python\pythonw.exe"),
                '"C:\\Users\\Example User\\Claude Restart\\claude_restart.py" --event-triggered --yes --wait 30',
            ),
            '"C:\\Program Files\\Python\\pythonw.exe" '
            '"C:\\Users\\Example User\\Claude Restart\\claude_restart.py" '
            "--event-triggered --yes --wait 30",
        )


class FrozenModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / "ClaudeRestart.exe"
        self.exe.write_bytes(b"")

    def frozen(self) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(mock.patch.object(app, "IS_FROZEN", True))
        stack.enter_context(mock.patch.object(sys, "executable", str(self.exe)))
        return stack

    def test_app_location_frozen_is_the_exe_folder(self) -> None:
        with self.frozen():
            self.assertEqual(app.app_entry(), self.exe)
            self.assertEqual(app.app_location(), self.root)

    def test_task_launcher_frozen_prefers_the_quiet_twin(self) -> None:
        with self.frozen():
            executable, arguments = app.task_launcher()
        self.assertEqual(executable, self.exe)
        self.assertEqual(arguments, app.TASK_ARGUMENTS)

        twin = self.root / "ClaudeRestart-quiet.exe"
        twin.write_bytes(b"")
        with self.frozen():
            executable, arguments = app.task_launcher()
        self.assertEqual(executable, twin)
        self.assertEqual(arguments, app.TASK_ARGUMENTS)
        self.assertEqual(
            app.build_task_action(executable, arguments),
            f'"{twin}" --event-triggered --yes --wait 30',
        )

    def test_elevation_request_frozen_has_no_script_argument(self) -> None:
        with self.frozen():
            target, parameters, workdir = app.elevation_request(["--yes", "--pause", "--elevated"])
        self.assertEqual(Path(target), self.exe)
        self.assertEqual(parameters, "--yes --pause --elevated")
        self.assertEqual(Path(workdir), self.root)

    def test_elevation_request_from_source_keeps_the_script_first(self) -> None:
        target, parameters, workdir = app.elevation_request(["--yes"])
        script = str(Path(app.__file__).resolve())
        self.assertEqual(Path(target), Path(sys.executable).resolve())
        self.assertTrue(parameters.startswith(script) or parameters.startswith(f'"{script}"'))
        self.assertTrue(parameters.endswith("--yes --elevated"))
        self.assertEqual(Path(workdir), Path(app.__file__).resolve().parent)

    @unittest.skipUnless(sys.platform == "win32", "task interpreter selection is Windows-only")
    def test_task_launcher_from_source_uses_python_and_the_script(self) -> None:
        executable, arguments = app.task_launcher()
        self.assertIn(executable.name.lower(), ("pythonw.exe", "python.exe"))
        self.assertTrue(arguments.startswith('"'))
        self.assertTrue(arguments.endswith(app.TASK_ARGUMENTS))


class ReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_save_writes_beside_the_tool(self) -> None:
        reporter = app.Reporter()
        reporter.lines.append("[TEST] hello")
        target = reporter.save(base=self.root)
        self.assertEqual(target, self.root / app.LOG_FILE_NAME)
        self.assertIn("[TEST] hello", target.read_text(encoding="utf-8"))

    def test_save_falls_back_when_the_tool_folder_is_unwritable(self) -> None:
        blocker = self.root / "not-a-directory"
        blocker.write_text("x", encoding="utf-8")
        fallback = self.root / "fallback"
        reporter = app.Reporter()
        reporter.lines.append("[TEST] fallback")
        target = reporter.save(base=blocker, fallback=fallback)
        self.assertEqual(target, fallback / app.LOG_FILE_NAME)
        self.assertTrue(target.is_file())

    def test_save_skips_an_empty_run(self) -> None:
        self.assertIsNone(app.Reporter().save(base=self.root))
        self.assertFalse((self.root / app.LOG_FILE_NAME).exists())


class TaskXmlTests(unittest.TestCase):
    def build(self) -> ET.Element:
        xml_text = app.build_task_xml(
            Path(r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe"),
            app.TASK_ARGUMENTS,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            Path(r"C:\Tools\ClaudeRestart"),
        )
        self.assertTrue(xml_text.startswith('<?xml version="1.0" encoding="UTF-16"?>'))
        self.assertNotIn("1.52386", xml_text)
        return ET.fromstring(xml_text.encode("utf-16"))

    def test_task_xml_sets_the_reviewed_settings(self) -> None:
        settings = self.build().find("t:Settings", TASK_NS)
        self.assertIsNotNone(settings)
        for tag, expected in app.TASK_SETTINGS:
            self.assertEqual(settings.findtext(f"t:{tag}", namespaces=TASK_NS), expected, tag)
        self.assertEqual(settings.findtext("t:DisallowStartIfOnBatteries", namespaces=TASK_NS), "false")
        self.assertEqual(settings.findtext("t:StopIfGoingOnBatteries", namespaces=TASK_NS), "false")
        self.assertEqual(settings.findtext("t:MultipleInstancesPolicy", namespaces=TASK_NS), "IgnoreNew")
        self.assertEqual(settings.findtext("t:ExecutionTimeLimit", namespaces=TASK_NS), "PT5M")

    def test_task_xml_principal_and_action(self) -> None:
        task = self.build()
        principal = task.find("t:Principals/t:Principal", TASK_NS)
        self.assertEqual(
            principal.findtext("t:UserId", namespaces=TASK_NS),
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        )
        self.assertEqual(principal.findtext("t:LogonType", namespaces=TASK_NS), "InteractiveToken")
        self.assertEqual(principal.findtext("t:RunLevel", namespaces=TASK_NS), "HighestAvailable")
        exec_node = task.find("t:Actions/t:Exec", TASK_NS)
        self.assertEqual(
            exec_node.findtext("t:Command", namespaces=TASK_NS),
            r"C:\Tools\ClaudeRestart\ClaudeRestart-quiet.exe",
        )
        self.assertEqual(exec_node.findtext("t:Arguments", namespaces=TASK_NS), app.TASK_ARGUMENTS)
        self.assertEqual(exec_node.findtext("t:WorkingDirectory", namespaces=TASK_NS), r"C:\Tools\ClaudeRestart")

    def test_task_xml_subscription_is_the_stable_xpath(self) -> None:
        trigger = self.build().find("t:Triggers/t:EventTrigger", TASK_NS)
        self.assertEqual(trigger.findtext("t:Enabled", namespaces=TASK_NS), "true")
        subscription = trigger.findtext("t:Subscription", namespaces=TASK_NS)
        self.assertIn(app.AUTO_RECOVERY_XPATH, subscription)
        self.assertIn(app.APPMODEL_LOG, subscription)
        query = ET.fromstring(subscription)  # the escaped QueryList must itself be well-formed
        self.assertEqual(query.tag, "QueryList")
        self.assertEqual(query.find("Query/Select").text, app.AUTO_RECOVERY_XPATH)


class MemberValidationTests(unittest.TestCase):
    OPAQUE = app.ProcessInfo(200, "<exited or inaccessible>", "", "", None, None)
    SAME = app.ProcessInfo(201, "claude.exe", r"C:\x\claude.exe", "", 1, 5)
    FOREIGN = app.ProcessInfo(202, "claude.exe", r"C:\x\claude.exe", "", 2, 5)
    LIVE_UNKNOWN_SESSION = app.ProcessInfo(203, "claude.exe", r"C:\x\claude.exe", "", None, 5)

    def test_member_the_kernel_no_longer_lists_counts_as_exited(self) -> None:
        self.assertEqual(
            app._partition_members([self.OPAQUE, self.SAME], 1, still_in_job=[201]),
            ([200], []),
        )

    def test_opaque_member_still_in_the_job_stops_the_repair(self) -> None:
        # Fail closed: the kernel still lists PID 200, so it is live but unverifiable.
        self.assertEqual(
            app._partition_members([self.OPAQUE, self.SAME], 1, still_in_job=[200, 201]),
            ([], [200]),
        )

    def test_foreign_or_unknown_sessions_are_never_exited(self) -> None:
        self.assertEqual(app._partition_members([self.SAME, self.FOREIGN], 1, still_in_job=[201, 202]), ([], [202]))
        self.assertEqual(app._partition_members([self.LIVE_UNKNOWN_SESSION], 1, still_in_job=[203]), ([], [203]))
        self.assertEqual(app._partition_members([self.LIVE_UNKNOWN_SESSION], 1, still_in_job=[]), ([], [203]))
        self.assertEqual(app._partition_members([self.SAME], None, still_in_job=[201]), ([], [201]))


class TriggerIdentityTests(unittest.TestCase):
    def package(self, application_id: str) -> app.PackageInfo:
        return app.PackageInfo(
            "Claude",
            "1.52386.3.0",
            "Claude_1.52386.3.0_x64__pzs8sxrjxfjjc",
            app.EXPECTED_PACKAGE_FAMILY,
            r"C:\Program Files\WindowsApps\fixture",
            application_id,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        )

    def test_matching_identity_has_no_problem(self) -> None:
        self.assertIsNone(app.trigger_identity_problem(self.package("Claude")))

    def test_changed_identity_is_reported(self) -> None:
        problem = app.trigger_identity_problem(self.package("ClaudeApp"))
        self.assertIn("Claude_pzs8sxrjxfjjc!ClaudeApp", problem)
        self.assertIn(app.AUTO_RECOVERY_APPLICATION, problem)


class ElevationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8, "x64 Windows layout")
    def test_shellexecuteinfo_layout_matches_win64(self) -> None:
        self.assertEqual(ctypes.sizeof(app.SHELLEXECUTEINFOW), 112)

    def test_reporter_persists_by_default(self) -> None:
        self.assertTrue(app.Reporter().persist)


class MainHardeningTests(unittest.TestCase):
    def test_stdin_none_is_not_interactive(self) -> None:
        with mock.patch.object(sys, "stdin", None):
            self.assertFalse(app._stdin_is_interactive())

    def test_pause_without_a_console_returns_quietly(self) -> None:
        with mock.patch.object(sys, "stdin", None):
            app._pause()

    def test_event_triggered_exit_codes_stay_zero_unless_internal_error(self) -> None:
        for code in (app.EXIT_OK, app.EXIT_ERROR, app.EXIT_SAFETY_STOP, app.EXIT_STALE_FOUND):
            self.assertEqual(app.event_triggered_exit_code(code), app.EXIT_OK)
        self.assertEqual(app.event_triggered_exit_code(app.EXIT_INTERNAL_ERROR), app.EXIT_INTERNAL_ERROR)

    def test_version_constant_is_semver(self) -> None:
        self.assertRegex(app.__version__, r"^\d+\.\d+\.\d+$")

    @unittest.skipUnless(sys.platform == "win32", "the CLI only runs on Windows")
    def test_version_flag_prints_the_version(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(Path(app.__file__).resolve()), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(app.__version__, completed.stdout)


if __name__ == "__main__":
    unittest.main()
