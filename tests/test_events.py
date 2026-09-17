"""The structured failure signal: which Windows events count as this failure."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402  (also puts the repository root on sys.path)

from clauderestart import events  # noqa: E402
from clauderestart.errors import RecoveryError  # noqa: E402
from clauderestart.package import EXPECTED_PACKAGE_FAMILY, PackageInfo  # noqa: E402


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


def fixture_package() -> PackageInfo:
    return PackageInfo(
        "Claude",
        "9.99999.1.0",
        "Claude_9.99999.1.0_x64__pzs8sxrjxfjjc",
        EXPECTED_PACKAGE_FAMILY,
        r"C:\Program Files\WindowsApps\fixture",
        "Claude",
        "S-1-5-21-1111111111-2222222222-3333333333-1001",
    )


class ShareViolationXPathTests(unittest.TestCase):
    def test_the_window_starts_at_the_launch_in_utc_to_the_millisecond(self) -> None:
        since = datetime(2026, 9, 16, 6, 40, 40, 505123, tzinfo=timezone(timedelta(hours=-5)))
        xpath = events.share_violation_xpath(since)
        self.assertIn("TimeCreated[@SystemTime>='2026-09-16T11:40:40.505Z']", xpath)
        for event_id in events.APP_ERROR_IDS:
            self.assertIn(f"EventID={event_id}", xpath)


@unittest.skipUnless(sys.platform == "win32", "runs the real event queries in Windows PowerShell")
class EventQueryFailureTests(unittest.TestCase):
    """Nothing found and could not look are different answers.

    An empty answer from a query that never ran lets a launch report GREEN, a trace report
    CLEAR, and an event-triggered run skip recovery. The error ids are the ones Get-WinEvent
    was observed to report on a test machine, elevated and under a restricted token.
    """

    QUERIES = (
        ("the trace and trigger query", lambda: events.auto_recovery_events(fixture_package(), minutes=10)),
        (
            "the post-launch query",
            lambda: events.appmodel_share_violations(fixture_package(), datetime.now(timezone.utc)),
        ),
    )

    def run_with(self, query, error_id: str, category: str, message: str) -> object:
        stand_in = support.failing_cmdlet("Get-WinEvent", ("LogName", "FilterXPath"), error_id, category, message)
        with support.powershell_with(stand_in):
            try:
                return query()
            except RecoveryError as exc:
                return exc

    def test_a_query_that_matched_nothing_is_no_events(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(
                    query,
                    events.NO_EVENTS_ERROR,
                    "ObjectNotFound",
                    "No events were found that match the specified selection criteria.",
                )
                self.assertEqual(found, [])

    def test_a_denied_log_is_an_error_not_an_empty_answer(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(
                    query,
                    "System.UnauthorizedAccessException",
                    "NotSpecified",
                    "Attempted to perform an unauthorized operation.",
                )
                self.assertIsInstance(found, RecoveryError)
                self.assertIn("The AppModel event log could not be read", str(found))

    def test_a_missing_log_is_an_error_even_though_it_is_also_not_found(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(
                    query,
                    "NoMatchingLogsFound",
                    "ObjectNotFound",
                    "There is not an event log on the localhost computer that matches.",
                )
                self.assertIsInstance(found, RecoveryError)

    def test_the_real_log_is_read_without_error(self) -> None:
        # Read only. A malformed query is an error from Windows, so this also proves the XPath
        # both queries build is accepted by the real event log service.
        self.assertIsInstance(events.auto_recovery_events(fixture_package(), minutes=1), list)
        tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
        self.assertEqual(events.appmodel_share_violations(fixture_package(), tomorrow), [])
        long_ago = datetime(2000, 1, 1, tzinfo=timezone.utc)
        self.assertIsInstance(events.appmodel_share_violations(fixture_package(), long_ago), list)


if __name__ == "__main__":
    unittest.main()
