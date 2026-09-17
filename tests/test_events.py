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

    # (error id, category, message) as Get-WinEvent reported each on the test machine.
    NO_EVENTS = (events.NO_EVENTS_ERROR, "ObjectNotFound", "No events were found that match the specified selection criteria.")
    DENIED = ("System.UnauthorizedAccessException", "NotSpecified", "Attempted to perform an unauthorized operation.")
    MISSING = ("NoMatchingLogsFound", "ObjectNotFound", "There is not an event log on the localhost computer that matches.")
    # The real reader writes a record it could not read with the exception message as the error id.
    UNREADABLE_RECORD = (
        "The description for the event could not be read.",
        "NotSpecified",
        "The description for the event could not be read.",
    )
    LOG_INFO_DENIED = (
        "LogInfoUnavailable",
        "NotSpecified",
        "Could not retrieve information about the log. Error: Attempted to perform an unauthorized operation.",
    )

    def stand_in(
        self,
        *,
        error=None,
        terminating: bool = False,
        records: int = 0,
        enabled: bool = True,
        list_log_error=None,
    ) -> str:
        """Get-WinEvent as a function: the log's state, fixture failure records, then an error."""
        report = support.ps_error(*error, terminating=terminating) if error else ""
        list_log_report = support.ps_error(*list_log_error, terminating=True) if list_log_error else ""
        xml = ERROR_EVENT.replace("'", "''")
        enabled_value = "$true" if enabled else "$false"
        return f"""
function Get-WinEvent {{
    [CmdletBinding()] param([string]$LogName, [string]$FilterXPath, [string]$ListLog)
    if ($ListLog) {{
{list_log_report}
        return [pscustomobject]@{{ LogName = $ListLog; IsEnabled = {enabled_value} }}
    }}
    for ($index = 0; $index -lt {records}; $index++) {{
        $record = [pscustomobject]@{{ RecordId = [long](233166 + $index); Id = 208; TimeCreated = Get-Date; Message = 'fixture' }}
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value {{ '{xml}' }}
        $record
    }}
{report}
}}
"""

    def run_with(self, query, **stand_in) -> object:
        with support.powershell_with(self.stand_in(**stand_in)):
            try:
                return query()
            except RecoveryError as exc:
                return exc

    def test_a_query_that_matched_nothing_is_no_events(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                self.assertEqual(self.run_with(query, error=self.NO_EVENTS), [])

    def test_a_denied_log_is_an_error_not_an_empty_answer(self) -> None:
        # A denied log throws, even when errors are only being collected.
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(query, error=self.DENIED, terminating=True)
                self.assertIsInstance(found, RecoveryError)
                self.assertIn("The AppModel event log could not be read", str(found))

    def test_a_missing_log_is_an_error_even_though_it_is_also_not_found(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(query, error=self.MISSING)
                self.assertIsInstance(found, RecoveryError)
                self.assertIn("The AppModel event log could not be read", str(found))

    def test_a_disabled_log_is_an_error_whether_or_not_it_holds_records(self) -> None:
        # A disabled log can still hold older records that the time filter then removes, which
        # would read as nothing new; so the state is checked before anything is read.
        for label, query in self.QUERIES:
            for records in (0, 1):
                with self.subTest(label, records=records):
                    error = self.NO_EVENTS if records == 0 else None
                    found = self.run_with(query, error=error, records=records, enabled=False)
                    self.assertIsInstance(found, RecoveryError)
                    self.assertIn("disabled", str(found))

    def test_a_log_whose_state_cannot_be_read_is_an_error(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                found = self.run_with(query, error=self.NO_EVENTS, list_log_error=self.LOG_INFO_DENIED)
                self.assertIsInstance(found, RecoveryError)
                self.assertIn("Could not retrieve information about the log", str(found))

    def test_a_trace_keeps_the_records_it_read_beside_one_it_could_not(self) -> None:
        trace = self.QUERIES[0][1]
        found = self.run_with(trace, error=self.UNREADABLE_RECORD, records=1)
        self.assertIsInstance(found, list, found)
        self.assertEqual(len(found), 1, found)

    def test_the_post_launch_check_fails_on_any_record_it_could_not_read(self) -> None:
        # That record might be the new failure, and GREEN must not rest on having skipped it.
        post_launch = self.QUERIES[1][1]
        found = self.run_with(post_launch, error=self.UNREADABLE_RECORD, records=1)
        self.assertIsInstance(found, RecoveryError)
        self.assertIn("The description for the event could not be read", str(found))

    def test_an_error_with_nothing_read_is_an_error(self) -> None:
        for label, query in self.QUERIES:
            with self.subTest(label):
                self.assertIsInstance(self.run_with(query, error=self.UNREADABLE_RECORD), RecoveryError)

    def test_a_query_the_real_log_throws_on_is_an_error(self) -> None:
        # Read only. The real cmdlet throws for a query it rejects, as it does for a denied log,
        # so this proves a thrown failure from the real cmdlet ends as an error, not no events.
        from clauderestart import shell

        for strict in (False, True):
            with self.subTest(strict=strict):
                script = events._read_events_function(strict=strict) + "\n@(Read-AppModelEvents '*[System[') | Out-Null"
                with self.assertRaises(RecoveryError) as stop:
                    shell.run_powershell(script)
                self.assertIn("The AppModel event log could not be read", str(stop.exception))

    def test_the_real_log_is_read_without_error(self) -> None:
        # Read only. A malformed query throws, so this proves the event log service accepts the
        # XPath both queries build. It cannot show that the time filter selects the right events,
        # because a time it cannot compare simply matches nothing; the next test shows that.
        self.assertIsInstance(events.auto_recovery_events(fixture_package(), minutes=1), list)
        tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
        self.assertEqual(events.appmodel_share_violations(fixture_package(), tomorrow), [])
        long_ago = datetime(2000, 1, 1, tzinfo=timezone.utc)
        self.assertIsInstance(events.appmodel_share_violations(fixture_package(), long_ago), list)

    def test_the_time_window_selects_from_the_moment_given(self) -> None:
        # Read only, against the System log, which holds events on every Windows machine: the
        # newest event is selected by a window starting one second before it, not one after.
        import json

        from clauderestart import shell

        newest = json.loads(
            shell.run_powershell(
                "$e = Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop; "
                "[pscustomobject]@{ RecordId = $e.RecordId; Id = $e.Id; "
                "Utc = $e.TimeCreated.ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress"
            )
        )
        moment = datetime.fromisoformat(newest["Utc"])

        def selected(since: datetime) -> bool:
            xpath = shell.ps_single_quote(events.share_violation_xpath(since, event_ids=(int(newest["Id"]),)))
            ids = json.loads(
                shell.run_powershell(
                    f"$ids = @(Get-WinEvent -LogName System -FilterXPath {xpath} -ErrorAction SilentlyContinue | "
                    "ForEach-Object { $_.RecordId }); ConvertTo-Json -InputObject @($ids) -Compress"
                )
                or "[]"
            )
            return int(newest["RecordId"]) in [int(value) for value in ids]

        self.assertTrue(selected(moment - timedelta(seconds=1)), newest)
        self.assertFalse(selected(moment + timedelta(seconds=1)), newest)


if __name__ == "__main__":
    unittest.main()
