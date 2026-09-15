"""The installed application identity versus the trigger identity."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import package as package_module  # noqa: E402


class TriggerIdentityTests(unittest.TestCase):
    def package(self, application_id: str) -> package_module.PackageInfo:
        return package_module.PackageInfo(
            "Claude",
            "1.52386.3.0",
            "Claude_1.52386.3.0_x64__pzs8sxrjxfjjc",
            package_module.EXPECTED_PACKAGE_FAMILY,
            r"C:\Program Files\WindowsApps\fixture",
            application_id,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        )

    def test_matching_identity_has_no_problem(self) -> None:
        self.assertIsNone(package_module.trigger_identity_problem(self.package("Claude")))

    def test_changed_identity_is_reported(self) -> None:
        problem = package_module.trigger_identity_problem(self.package("ClaudeApp"))
        self.assertIn("Claude_pzs8sxrjxfjjc!ClaudeApp", problem)
        self.assertIn(package_module.AUTO_RECOVERY_APPLICATION, problem)


if __name__ == "__main__":
    unittest.main()
