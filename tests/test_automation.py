from __future__ import annotations

from pathlib import Path
import sys
import unittest


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

    def test_task_action_quotes_python_and_script_paths(self) -> None:
        action = app.build_task_action(
            Path(r"C:\Program Files\Python\pythonw.exe"),
            Path(r"C:\Users\Example User\Claude Restart\claude_restart.py"),
        )
        self.assertEqual(
            action,
            '"C:\\Program Files\\Python\\pythonw.exe" '
            '"C:\\Users\\Example User\\Claude Restart\\claude_restart.py" '
            "--event-triggered --yes --wait 30",
        )


if __name__ == "__main__":
    unittest.main()
