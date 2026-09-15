"""What counts as a protected folder, judged from security descriptors.

These fixtures go through the real Windows SDDL parser, so the verdicts are produced by
the same reader that runs against a real folder. Every rule gets a case that fails, so
the check cannot quietly pass everything.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
