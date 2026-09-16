"""What counts as a protected folder, judged from security descriptors.

These fixtures go through the real Windows SDDL parser, so the verdicts are produced by
the same reader that runs against a real folder. Every rule gets a case that fails, so
the check cannot quietly pass everything.
"""

from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import security, winapi  # noqa: E402


CANONICAL = security.PROTECTED_SDDL
UNTRUSTED_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def setUpModule() -> None:
    winapi.configure()


@unittest.skipUnless(sys.platform == "win32", "security descriptors are Windows-only")
class OwnedFolderVerdictTests(unittest.TestCase):
    def test_the_canonical_form_passes(self) -> None:
        report = security.verify_sddl(CANONICAL)
        self.assertTrue(report.ok, report.problems)
        self.assertEqual(report.owner_sid, security.SID_ADMINISTRATORS)
        self.assertEqual(report.blocking, [])

    def test_an_unprotected_list_is_a_repairable_problem(self) -> None:
        report = security.verify_sddl("O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
        self.assertFalse(report.ok)
        self.assertTrue(report.repairable, report.problems)
        self.assertTrue(any("inherits" in problem for problem in report.problems), report.problems)

    def test_the_inherit_only_creator_owner_entry_is_repairable_not_blocking(self) -> None:
        """The entry Program Files seeds children with must not refuse the folder.

        It grants nothing on the folder itself, and the repair replaces the whole list, so
        blocking on it would refuse exactly the pre-existing folders the repair exists for.
        """
        report = security.verify_sddl(CANONICAL + "(A;OICIIO;GA;;;CO)")
        self.assertFalse(report.ok)
        self.assertEqual(report.blocking, [], report.blocking)
        self.assertTrue(report.repairable, report.problems)

    def test_a_creator_owner_entry_that_applies_to_the_folder_is_blocking(self) -> None:
        # Without the inherit-only flag the same entry really does grant on this folder.
        report = security.verify_sddl(CANONICAL + "(A;OICI;GA;;;CO)")
        self.assertFalse(report.ok)
        self.assertTrue(report.blocking, report.problems)

    def test_an_inherit_only_entry_for_another_principal_is_still_blocking(self) -> None:
        # The exception is for CREATOR OWNER alone, not for inherit-only entries in general.
        report = security.verify_sddl(CANONICAL + "(A;OICIIO;GA;;;BU)")
        self.assertFalse(report.ok)
        self.assertTrue(report.blocking, report.problems)

    def test_a_folder_with_no_permission_list_is_blocking(self) -> None:
        # A descriptor with no list at all grants everyone everything. This is the branch
        # that refuses it, for the root and for every file inside it.
        report = security.verify_sddl("O:BAG:SY")
        self.assertFalse(report.ok)
        self.assertFalse(report.repairable)
        self.assertTrue(any("no permission list" in problem for problem in report.blocking), report.blocking)

    def test_an_object_entry_is_blocking_because_it_is_not_interpreted(self) -> None:
        # An object entry carries GUIDs this reader does not interpret, so it is never
        # treated as harmless, the same rule as a conditional entry.
        report = security.verify_sddl(CANONICAL + "(OA;OICI;FA;;;BU)")
        self.assertFalse(report.ok)
        self.assertTrue(report.blocking, report.problems)

    def test_write_access_for_users_is_blocking(self) -> None:
        report = security.verify_sddl("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
        self.assertFalse(report.ok)
        self.assertFalse(report.repairable)
        self.assertTrue(any(security.SID_USERS in problem for problem in report.blocking), report.blocking)

    def test_an_untrusted_owner_is_blocking(self) -> None:
        report = security.verify_sddl(
            f"O:{UNTRUSTED_SID}G:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("owned by" in problem for problem in report.blocking), report.blocking)

    def test_an_empty_list_denies_everything_and_still_fails(self) -> None:
        report = security.verify_sddl("O:BAG:SYD:P")
        self.assertFalse(report.ok)
        self.assertTrue(any("expected three entries" in problem for problem in report.problems), report.problems)

    def test_an_extra_entry_fails_even_when_it_looks_harmless(self) -> None:
        report = security.verify_sddl(
            "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;FR;;;WD)"
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("expected three entries" in problem for problem in report.problems), report.problems)

    def test_a_deny_entry_is_blocking(self) -> None:
        # A deny for Administrators would stop the elevated task from running its own file.
        report = security.verify_sddl(
            "O:BAG:SYD:P(D;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("denies access" in problem for problem in report.blocking), report.blocking)

    def test_a_conditional_entry_is_blocking_because_it_is_not_interpreted(self) -> None:
        report = security.verify_sddl(
            "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
            "(XA;OICI;FA;;;BU;(@USER.Title==\"x\"))"
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("unsupported type" in problem for problem in report.blocking), report.blocking)

    def test_every_single_write_bit_is_caught_for_an_untrusted_principal(self) -> None:
        for bit, name in security.WRITE_BIT_NAMES:
            for sid in ("BU", UNTRUSTED_SID):
                with self.subTest(bit=name, sid=sid):
                    report = security.verify_sddl(
                        "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
                        f"(A;OICI;0x{bit:08x};;;{sid})"
                    )
                    self.assertFalse(report.ok)
                    self.assertTrue(report.blocking, f"{name} for {sid} was not reported")

    def test_read_only_access_for_an_untrusted_principal_is_not_blocking(self) -> None:
        # Extra read access is a deviation worth repairing, not a reason to refuse.
        report = security.verify_sddl(
            "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
            f"(A;OICI;0x1200a9;;;{UNTRUSTED_SID})"
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.blocking, [])
        self.assertTrue(report.repairable)


@unittest.skipUnless(sys.platform == "win32", "security descriptors are Windows-only")
class ChildVerdictTests(unittest.TestCase):
    def test_inherited_canonical_entries_pass(self) -> None:
        report = security.verify_sddl(
            "O:BAG:SYD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)", inherited=True
        )
        self.assertTrue(report.ok, report.problems)

    def test_an_explicit_entry_on_a_child_is_a_problem(self) -> None:
        report = security.verify_sddl(
            "O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)", inherited=True
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("is explicit" in problem for problem in report.problems), report.problems)

    def test_an_added_write_entry_on_a_child_is_blocking(self) -> None:
        report = security.verify_sddl(
            "O:BAG:SYD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"
            f"(A;;FA;;;{UNTRUSTED_SID})",
            inherited=True,
        )
        self.assertFalse(report.ok)
        self.assertTrue(report.blocking, report.problems)


@unittest.skipUnless(sys.platform == "win32", "these read a real handle")
class FolderIdentityTests(unittest.TestCase):
    """The two refusals scan_tree applies to a folder as an object in its own right.

    Everything else it does walks the entries inside a folder, so without these the root
    itself, and every subdirectory, is judged only by its permission list.
    """

    def problems(self, *, reparse: bool, final: str) -> list[str]:
        stub = SimpleNamespace(
            is_reparse_point=lambda: reparse, final_path=lambda: final, close=lambda: None
        )
        with mock.patch.object(security.winapi, "open_locked", return_value=stub):
            return security._directory_write_problems(Path(r"C:\ProgramData\fixture"), support.FakeFileSecurity())

    def test_a_folder_that_is_a_reparse_point_is_blocking(self) -> None:
        problems = self.problems(reparse=True, final="")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("reparse point", problems[0])

    def test_a_folder_that_does_not_resolve_to_itself_is_blocking(self) -> None:
        # A folder reached through a path that resolves elsewhere is the one state no other
        # check anywhere compares.
        problems = self.problems(reparse=False, final=r"c:\somewhere\else")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("does not resolve to itself", problems[0])


if __name__ == "__main__":
    unittest.main()
