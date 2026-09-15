"""Identity of the installed Claude Desktop package."""

from __future__ import annotations

from dataclasses import dataclass
import json

from . import shell
from .errors import RecoveryError, SafetyStop


APP_NAME = "Claude"
EXPECTED_PACKAGE_FAMILY = "Claude_pzs8sxrjxfjjc"
AUTO_RECOVERY_APPLICATION_ID = "Claude"
AUTO_RECOVERY_APPLICATION = f"{EXPECTED_PACKAGE_FAMILY}!{AUTO_RECOVERY_APPLICATION_ID}"


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    package_full_name: str
    package_family_name: str
    install_location: str
    application_id: str
    user_sid: str


def version_key(value: str) -> tuple[int, int, int, int]:
    pieces = value.split(".")
    if len(pieces) != 4 or any(not piece.isdigit() for piece in pieces):
        raise SafetyStop(f"Expected a four-part numeric version; observed {value!r}.")
    return tuple(int(piece) for piece in pieces)  # type: ignore[return-value]


def get_claude_package() -> PackageInfo:
    script = r"""
$result = @(
    Get-AppxPackage -Name 'Claude' -ErrorAction Stop |
    Sort-Object Version -Descending |
    ForEach-Object {
        $applicationId = 'Claude'
        try {
            $manifest = Get-AppxPackageManifest -Package $_.PackageFullName -ErrorAction Stop
            $manifestId = [string](@($manifest.Package.Applications.Application)[0].Id)
            if ($manifestId) { $applicationId = $manifestId }
        } catch {}
        [pscustomobject]@{
            Name = $_.Name
            Version = $_.Version.ToString()
            PackageFullName = $_.PackageFullName
            PackageFamilyName = $_.PackageFamilyName
            InstallLocation = $_.InstallLocation
            ApplicationId = $applicationId
            UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        }
    }
)
ConvertTo-Json -InputObject @($result) -Compress -Depth 4
"""
    raw = shell.run_powershell(script)
    if not raw:
        raise RecoveryError("Claude is not registered for the current Windows user.")
    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]
    if len(data) != 1:
        versions = ", ".join(str(item.get("Version")) for item in data) or "none"
        raise SafetyStop(f"Expected one registered Claude package; observed: {versions}.")
    item = data[0]
    package = PackageInfo(
        name=str(item["Name"]),
        version=str(item["Version"]),
        package_full_name=str(item["PackageFullName"]),
        package_family_name=str(item["PackageFamilyName"]),
        install_location=str(item["InstallLocation"]),
        application_id=str(item["ApplicationId"]),
        user_sid=str(item["UserSid"]),
    )
    if package.name != APP_NAME or package.package_family_name != EXPECTED_PACKAGE_FAMILY:
        raise SafetyStop(
            "The registered package identity is not the reviewed Claude package: "
            f"{package.package_family_name}."
        )
    version_key(package.version)
    expected_start = f"{package.name}_{package.version}"
    if not package.package_full_name.startswith(expected_start):
        raise SafetyStop(f"Unexpected package full name: {package.package_full_name}.")
    return package


def trigger_identity_problem(package: PackageInfo) -> str | None:
    """Explain why the event trigger could never fire for this package, or return None."""
    installed = f"{package.package_family_name}!{package.application_id}"
    if installed == AUTO_RECOVERY_APPLICATION:
        return None
    return (
        f"Installed application id {installed} differs from the trigger identity "
        f"{AUTO_RECOVERY_APPLICATION}; automatic recovery would never fire until the tool is updated."
    )
