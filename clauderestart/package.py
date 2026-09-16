"""Identity of the installed Claude Desktop package.

The application id is never guessed. When the manifest cannot be read, lists no
application, or lists several that do not resolve under the documented rule, the id
is unknown and every destructive or installing path refuses to continue.
"""

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
    application_id: str | None
    user_sid: str
    application_id_error: str = ""

    def __post_init__(self) -> None:
        # Exactly one of the two states is legal: a confirmed id, or no id with a reason.
        if (self.application_id is None) != bool(self.application_id_error):
            raise ValueError(
                "PackageInfo needs either a confirmed application_id or an application_id_error, not both "
                f"(id={self.application_id!r}, error={self.application_id_error!r})."
            )

    @property
    def aumid(self) -> str | None:
        """The AppUserModelID, or None when the application id is unknown."""
        if self.application_id is None:
            return None
        return f"{self.package_family_name}!{self.application_id}"


def version_key(value: str) -> tuple[int, int, int, int]:
    pieces = value.split(".")
    if len(pieces) != 4 or any(not piece.isdigit() for piece in pieces):
        raise SafetyStop(f"Expected a four-part numeric version; observed {value!r}.")
    return tuple(int(piece) for piece in pieces)  # type: ignore[return-value]


def select_application_id(ids: object, manifest_error: str) -> tuple[str | None, str]:
    """Apply the documented rule to the manifest's application ids.

    One application selects that id. Several applications select the expected id only
    when exactly one of them equals it. Anything else is unknown, with the reason.
    """
    if isinstance(ids, str):
        ids = [ids]
    elif ids is None:
        ids = []
    elif not isinstance(ids, (list, tuple)):
        ids = [ids]
    cleaned = [str(value).strip() for value in ids if str(value).strip()]
    if manifest_error:
        return None, f"the package manifest could not be read: {manifest_error}"
    if not cleaned:
        return None, "the package manifest listed no applications"
    if len(cleaned) == 1:
        return cleaned[0], ""
    matches = [value for value in cleaned if value == AUTO_RECOVERY_APPLICATION_ID]
    if len(matches) == 1:
        return matches[0], ""
    return None, f"the package manifest lists {len(cleaned)} applications: {', '.join(cleaned)}"


def get_claude_package() -> PackageInfo:
    script = r"""
$result = @(
    Get-AppxPackage -Name 'Claude' -ErrorAction Stop |
    Sort-Object Version -Descending |
    ForEach-Object {
        $package = $_
        $ids = @()
        $manifestError = ''
        try {
            $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
            $ids = @(@($manifest.Package.Applications.Application) | ForEach-Object { [string]$_.Id })
        } catch {
            $manifestError = [string]$_.Exception.Message
            if (-not $manifestError) { $manifestError = 'Get-AppxPackageManifest failed' }
        }
        [pscustomobject]@{
            Name = $package.Name
            Version = $package.Version.ToString()
            PackageFullName = $package.PackageFullName
            PackageFamilyName = $package.PackageFamilyName
            InstallLocation = $package.InstallLocation
            ApplicationIds = @($ids)
            ManifestError = $manifestError
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
    application_id, application_id_error = select_application_id(
        item.get("ApplicationIds"), str(item.get("ManifestError") or "")
    )
    package = PackageInfo(
        name=str(item["Name"]),
        version=str(item["Version"]),
        package_full_name=str(item["PackageFullName"]),
        package_family_name=str(item["PackageFamilyName"]),
        install_location=str(item["InstallLocation"]),
        application_id=application_id,
        user_sid=str(item["UserSid"]),
        application_id_error=application_id_error,
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
    if package.application_id is None:
        return (
            f"The installed Claude application id could not be established ({package.application_id_error}), "
            f"so it cannot be matched against the trigger identity {AUTO_RECOVERY_APPLICATION}."
        )
    installed = package.aumid
    if installed == AUTO_RECOVERY_APPLICATION:
        return None
    return (
        f"Installed application id {installed} differs from the trigger identity "
        f"{AUTO_RECOVERY_APPLICATION}; automatic recovery would never fire until the tool is updated."
    )
