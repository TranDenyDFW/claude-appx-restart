"""The application id rule: confirmed, or unknown and refused.

The identity is never guessed. Every case that cannot resolve to exactly one id must
leave application_id None with a reason, and every installing or terminating path must
refuse on that.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import package as package_module  # noqa: E402
from clauderestart.errors import RecoveryError, SafetyStop  # noqa: E402


def manifest_row(*, ids: object = ("Claude",), error: str = "", executables: object = None) -> str:
    return json.dumps(
        [
            {
                "Name": "Claude",
                "Version": "1.52386.6.0",
                "PackageFullName": "Claude_1.52386.6.0_x64__pzs8sxrjxfjjc",
                "PackageFamilyName": package_module.EXPECTED_PACKAGE_FAMILY,
                "InstallLocation": r"C:\Program Files\WindowsApps\fixture",
                "ApplicationIds": list(ids) if isinstance(ids, (list, tuple)) else ids,
                "ApplicationExecutables": executables,
                "ManifestError": error,
                "UserSid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
            }
        ]
    )


def query(**kwargs: object) -> package_module.PackageInfo:
    with mock.patch.object(package_module.shell, "run_powershell", return_value=manifest_row(**kwargs)):
        return package_module.get_claude_package()


class ExecutableTests(unittest.TestCase):
    """The executable the error dialog is matched against, read and never guessed."""

    def test_the_selected_application_executable_is_read(self) -> None:
        package = query(
            ids=("Claude",), executables=[{"Id": "Claude", "Executable": r"app\Claude.exe"}]
        )
        self.assertEqual(package.application_executable, r"app\Claude.exe")

    def test_the_executable_follows_the_selected_id_not_the_position(self) -> None:
        package = query(
            ids=("Helper", "Claude"),
            executables=[
                {"Id": "Helper", "Executable": r"app\helper.exe"},
                {"Id": "Claude", "Executable": r"app\Claude.exe"},
            ],
        )
        self.assertEqual(package.application_id, "Claude")
        self.assertEqual(package.application_executable, r"app\Claude.exe")

    def test_a_single_entry_sent_as_an_object_is_accepted(self) -> None:
        # PowerShell collapses a one element array to an object in JSON.
        package = query(ids=("Claude",), executables={"Id": "Claude", "Executable": r"app\Claude.exe"})
        self.assertEqual(package.application_executable, r"app\Claude.exe")

    def test_nothing_is_guessed(self) -> None:
        self.assertEqual(query(ids=("Claude",), executables=None).application_executable, "")
        self.assertEqual(query(ids=(), error="denied").application_executable, "")
        duplicated = [
            {"Id": "Claude", "Executable": r"app\a.exe"},
            {"Id": "Claude", "Executable": r"app\b.exe"},
        ]
        self.assertEqual(package_module.executable_for(duplicated, "Claude"), "")
        self.assertEqual(package_module.executable_for([{"Id": "Other", "Executable": "x.exe"}], "Claude"), "")
        self.assertEqual(package_module.executable_for([{"Id": "Claude", "Executable": "x.exe"}], None), "")


class SelectionRuleTests(unittest.TestCase):
    def test_one_application_is_confirmed(self) -> None:
        package = query(ids=("Claude",))
        self.assertEqual(package.application_id, "Claude")
        self.assertEqual(package.application_id_error, "")
        self.assertEqual(package.aumid, package_module.AUTO_RECOVERY_APPLICATION)
        self.assertIsNone(package_module.trigger_identity_problem(package))

    def test_one_different_application_is_confirmed_but_reported(self) -> None:
        package = query(ids=("ClaudeApp",))
        self.assertEqual(package.application_id, "ClaudeApp")
        problem = package_module.trigger_identity_problem(package)
        self.assertIn("Claude_pzs8sxrjxfjjc!ClaudeApp", problem)
        self.assertIn(package_module.AUTO_RECOVERY_APPLICATION, problem)

    def test_several_applications_with_exactly_one_expected_id_resolve(self) -> None:
        package = query(ids=("Updater", "Claude"))
        self.assertEqual(package.application_id, "Claude")
        self.assertIsNone(package_module.trigger_identity_problem(package))

    def test_manifest_failure_is_unknown_and_keeps_the_error(self) -> None:
        package = query(ids=(), error="Get-AppxPackageManifest: access is denied")
        self.assertIsNone(package.application_id)
        self.assertIn("access is denied", package.application_id_error)
        self.assertIsNone(package.aumid)
        self.assertIn(package_module.AUTO_RECOVERY_APPLICATION, package_module.trigger_identity_problem(package))

    def test_malformed_manifest_reported_as_an_error_is_unknown(self) -> None:
        package = query(ids=(), error="Data at the root level is invalid. Line 1, position 1.")
        self.assertIsNone(package.application_id)
        self.assertIn("Line 1", package.application_id_error)

    def test_empty_application_list_is_unknown(self) -> None:
        package = query(ids=())
        self.assertIsNone(package.application_id)
        self.assertIn("listed no applications", package.application_id_error)

    def test_blank_ids_count_as_no_applications(self) -> None:
        package = query(ids=("", "   "))
        self.assertIsNone(package.application_id)
        self.assertIn("listed no applications", package.application_id_error)

    def test_ambiguous_applications_are_unknown(self) -> None:
        package = query(ids=("Updater", "Helper"))
        self.assertIsNone(package.application_id)
        self.assertIn("lists 2 applications", package.application_id_error)
        self.assertIn("Updater", package.application_id_error)

    def test_duplicate_expected_ids_are_ambiguous(self) -> None:
        package = query(ids=("Claude", "Claude"))
        self.assertIsNone(package.application_id)
        self.assertIn("lists 2 applications", package.application_id_error)

    def test_a_single_id_sent_as_a_scalar_is_accepted(self) -> None:
        # PowerShell can serialize a one-element array as a scalar.
        package = query(ids="Claude")
        self.assertEqual(package.application_id, "Claude")


class InvariantTests(unittest.TestCase):
    def info(self, application_id: str | None, error: str) -> package_module.PackageInfo:
        return package_module.PackageInfo(
            "Claude",
            "1.52386.6.0",
            "Claude_1.52386.6.0_x64__pzs8sxrjxfjjc",
            package_module.EXPECTED_PACKAGE_FAMILY,
            r"C:\Program Files\WindowsApps\fixture",
            application_id,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            error,
        )

    def test_positional_construction_without_an_error_still_works(self) -> None:
        self.assertEqual(self.info("Claude", "").application_id, "Claude")

    def test_unknown_id_without_a_reason_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.info(None, "")

    def test_confirmed_id_with_a_reason_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.info("Claude", "the package manifest listed no applications")


class RefusalTests(unittest.TestCase):
    def unknown_package(self) -> package_module.PackageInfo:
        return query(ids=(), error="Get-AppxPackageManifest failed")

    def test_launch_refuses_an_unknown_identity(self) -> None:
        from clauderestart import recovery, reporting

        with self.assertRaises(RecoveryError) as stop:
            recovery.launch_and_verify(self.unknown_package(), reporting.Reporter(), 3)
        self.assertIn("application id could not be established", str(stop.exception))

    def test_install_refuses_an_unknown_identity(self) -> None:
        from clauderestart import cli, reporting

        reporter = reporting.Reporter()
        with mock.patch.object(cli, "get_claude_package", return_value=self.unknown_package()), mock.patch.object(
            cli.task, "register_task_xml"
        ) as register:
            with self.assertRaises(SafetyStop):
                cli.install_auto_recovery(reporter)
        register.assert_not_called()


if __name__ == "__main__":
    unittest.main()
