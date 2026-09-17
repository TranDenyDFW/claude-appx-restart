"""Structured Windows events for the Claude 0x80070020 launch failure."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import xml.etree.ElementTree as ET

from . import shell
from .errors import RecoveryError
from .package import AUTO_RECOVERY_APPLICATION, PackageInfo


APPMODEL_LOG = "Microsoft-Windows-AppModel-Runtime/Admin"
APP_ERROR_IDS = (208, 215)
SHARE_VIOLATION_HEX = "0x80070020"
SHARE_VIOLATION_DECIMAL = "2147942432"
# The error id Get-WinEvent reports for a query that matched no events, and nothing else.
NO_EVENTS_ERROR = "NoMatchingEventsFound"
AUTO_RECOVERY_XPATH = (
    "*[System[Provider[@Name='Microsoft-Windows-AppModel-Runtime'] and EventID=208] "
    "and EventData[Data[@Name='ApplicationName']='Claude_pzs8sxrjxfjjc!Claude' "
    "and Data[@Name='ErrorCode']='2147942432']]"
)


def _event_parts(xml_text: str) -> tuple[str, int | None, int | None, dict[str, str]]:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    provider = root.find("./e:System/e:Provider", namespace)
    event_id = root.findtext("./e:System/e:EventID", default="", namespaces=namespace)
    record_id = root.findtext("./e:System/e:EventRecordID", default="", namespaces=namespace)
    data = {
        str(node.attrib.get("Name", "")): str(node.text or "")
        for node in root.findall("./e:EventData/e:Data", namespace)
    }
    return (
        "" if provider is None else str(provider.attrib.get("Name", "")),
        int(event_id) if event_id.isdigit() else None,
        int(record_id) if record_id.isdigit() else None,
        data,
    )


def is_auto_recovery_event(xml_text: str) -> bool:
    """Return True only for the structured Claude 0x80070020 launch failure."""
    try:
        provider, event_id, _record_id, data = _event_parts(xml_text)
    except (ET.ParseError, ValueError):
        return False
    return (
        provider == "Microsoft-Windows-AppModel-Runtime"
        and event_id == 208
        and data.get("ApplicationName") == AUTO_RECOVERY_APPLICATION
        and data.get("ErrorCode") == SHARE_VIOLATION_DECIMAL
    )


def auto_recovery_events(
    package: PackageInfo | None = None,
    *,
    minutes: int = 180,
) -> list[dict[str, object]]:
    if minutes < 1 or minutes > 10080:
        raise RecoveryError("Trace window must be between 1 minute and 7 days.")
    xpath = shell.ps_single_quote(AUTO_RECOVERY_XPATH)
    script = f"""
{_read_events_function()}
$cutoff = (Get-Date).AddMinutes(-{minutes})
$result = @(
    Read-AppModelEvents {xpath} |
    Where-Object TimeCreated -ge $cutoff |
    ForEach-Object {{
        [pscustomobject]@{{
            RecordId = [long]$_.RecordId
            TimeCreated = $_.TimeCreated.ToString('o')
            Xml = $_.ToXml()
        }}
    }}
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = shell.run_powershell(script, timeout=30)
    rows = json.loads(raw) if raw else []
    if isinstance(rows, dict):
        rows = [rows]
    found: list[dict[str, object]] = []
    for row in rows:
        xml_text = str(row.get("Xml") or "")
        if not is_auto_recovery_event(xml_text):
            continue
        _provider, _event_id, record_id, data = _event_parts(xml_text)
        if package is not None and data.get("PackageName") != package.package_full_name:
            continue
        found.append(
            {
                "record_id": record_id,
                "time_created": str(row.get("TimeCreated") or ""),
                "package_name": data.get("PackageName", ""),
                "application_name": data.get("ApplicationName", ""),
                "error_code": data.get("ErrorCode", ""),
            }
        )
    return found


def share_violation_xpath(since: datetime) -> str:
    """Select the AppModel error events logged at or after `since`."""
    moment = since.astimezone(timezone.utc)
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    ids = " or ".join(f"EventID={event_id}" for event_id in APP_ERROR_IDS)
    return f"*[System[({ids}) and TimeCreated[@SystemTime>='{stamp}']]]"


def _read_events_function() -> str:
    """A PowerShell function that reads the AppModel log and fails when it cannot.

    Only the error Get-WinEvent reports for a query that matched nothing means there are no
    events. Anything else, a denied or missing log among them, exits non-zero so the caller
    gets an error instead of an empty answer: an empty answer lets a launch report GREEN, a
    trace report CLEAR, and an event-triggered run skip recovery, none of them having looked.
    The XPath form is used because the -FilterHashtable form reports a denied log as a query
    that matched nothing.
    """
    log_name = shell.ps_single_quote(APPMODEL_LOG)
    return f"""
function Read-AppModelEvents([string]$XPath) {{
    try {{
        return @(Get-WinEvent -LogName {log_name} -FilterXPath $XPath -ErrorAction Stop)
    }} catch {{
        if ($_.FullyQualifiedErrorId -like '{NO_EVENTS_ERROR},*') {{
            return @()
        }}
        [Console]::Error.WriteLine('The AppModel event log could not be read: ' + $_.Exception.Message)
        exit 1
    }}
}}
"""


def appmodel_share_violations(package: PackageInfo, since: datetime) -> list[dict[str, object]]:
    package_name = shell.ps_single_quote(package.package_full_name)
    xpath = shell.ps_single_quote(share_violation_xpath(since))
    newline = chr(96) + "n"  # a PowerShell escaped newline, built from parts for the shell scanners
    script = f"""
{_read_events_function()}
$package = {package_name}
$result = @(
    Read-AppModelEvents {xpath} |
    ForEach-Object {{
        $text = $_.ToXml() + "{newline}" + $_.Message
        if ($text.Contains($package) -and (
            $text.Contains('0x80070020') -or
            $text.Contains('2147942432') -or
            $text.Contains('-2147024864')
        )) {{
            [pscustomobject]@{{
                Id = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Message = $_.Message
            }}
        }}
    }}
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = shell.run_powershell(script, timeout=30)
    data = json.loads(raw) if raw else []
    if isinstance(data, dict):
        data = [data]
    return list(data)
