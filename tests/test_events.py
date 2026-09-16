"""The structured failure signal: which Windows events count as this failure."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401  (puts the repository root on sys.path)

from clauderestart import events  # noqa: E402


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


def changed_event(
    *,
    event_id: int = 208,
    application: str = "Claude_pzs8sxrjxfjjc!Claude",
    error: str = "2147942432",
) -> str:
    return (
        ERROR_EVENT.replace("<EventID>208</EventID>", f"<EventID>{event_id}</EventID>")
        .replace("Claude_pzs8sxrjxfjjc!Claude", application)
        .replace('<Data Name="ErrorCode">2147942432</Data>', f'<Data Name="ErrorCode">{error}</Data>')
    )


class EventAutomationTests(unittest.TestCase):
    def test_exact_structured_failure_is_selected_across_package_versions(self) -> None:
        self.assertTrue(events.is_auto_recovery_event(ERROR_EVENT))

    def test_nearby_events_are_rejected(self) -> None:
        self.assertFalse(events.is_auto_recovery_event(changed_event(event_id=215)))
        self.assertFalse(events.is_auto_recovery_event(changed_event(application="Other.App!Main")))
        self.assertFalse(events.is_auto_recovery_event(changed_event(error="5")))

    def test_scheduler_xpath_uses_stable_structured_fields_not_package_version(self) -> None:
        self.assertIn("EventID=208", events.AUTO_RECOVERY_XPATH)
        self.assertIn("Claude_pzs8sxrjxfjjc!Claude", events.AUTO_RECOVERY_XPATH)
        self.assertIn("2147942432", events.AUTO_RECOVERY_XPATH)
        self.assertNotIn("1.52386", events.AUTO_RECOVERY_XPATH)


if __name__ == "__main__":
    unittest.main()
