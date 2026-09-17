"""Closing the stale activation error dialog, and never closing anything else.

The production fixture is the window captured from a real incident: a TaskDialog shown by
sihost.exe, titled with the path of the Claude executable that failed to start. Every rule
gets a case where it alone fails, so no rule can be deleted without a test turning red.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import cli, dialogs, recovery, reporting  # noqa: E402
from clauderestart.package import EXPECTED_PACKAGE_FAMILY, PackageInfo  # noqa: E402


INSTALL = r"C:\Program Files\WindowsApps\Claude_2.110.0.0_x64__pzs8sxrjxfjjc"
TITLE = INSTALL + r"\app\claude.exe"
SIHOST = r"C:\Windows\System32\sihost.exe"
EXPLORER = r"C:\Windows\explorer.exe"
PYTHON = r"C:\Python314\python.exe"
DIALOG = 0x150786
SHELL_PID = 9704
TASK_DIALOG_TREE = ("DirectUIHWND", "CtrlNotifySink", "ScrollBar", "SysLink", "Button")


def package(executable: str = r"app\Claude.exe", install: str = INSTALL) -> PackageInfo:
    return PackageInfo(
        "Claude",
        "2.110.0.0",
        "Claude_2.110.0.0_x64__pzs8sxrjxfjjc",
        EXPECTED_PACKAGE_FAMILY,
        install,
        "Claude",
        "S-1-5-21-1111111111-2222222222-3333333333-1001",
        "",
        executable,
    )


class FakeWindows:
    """A scripted desktop: windows, the processes that own them, and a manual clock."""

    def __init__(self) -> None:
        self.windows: dict[int, dict[str, object]] = {}
        self.processes: dict[int, tuple[str, int | None]] = {
            SHELL_PID: (SIHOST, 1),
            4321: (EXPLORER, 1),
            555: (PYTHON, 1),
            666: (r"C:\Windows\Temp\sihost.exe", 1),
            777: (SIHOST, 2),
        }
        self.session_id: int | None = 1
        self.windir = Path(r"C:\WINDOWS")
        self.clock = 0.0
        self.clicked: list[int] = []
        self.posted: list[int] = []
        self.on_click: dict[int, str] = {}
        self.on_close: dict[int, str] = {}
        self.raise_on_click: Exception | None = None

    def add_dialog(
        self,
        hwnd: int = DIALOG,
        *,
        title: str = TITLE,
        pid: int = SHELL_PID,
        cls: str = "#32770",
        owner: int = 0,
        visible: bool = True,
        children: tuple[str, ...] = TASK_DIALOG_TREE,
        button_visible: bool = True,
        button_enabled: bool = True,
    ) -> int:
        kids = []
        for index, name in enumerate(children):
            child = hwnd * 100 + index + 1
            is_button = name == "Button"
            self.windows[child] = {
                "cls": name,
                "title": "OK" if is_button else "",
                "owner": 0,
                "visible": button_visible if is_button else True,
                "enabled": button_enabled if is_button else True,
                "pid": pid,
                "children": [],
                "top": False,
            }
            kids.append(child)
        self.windows[hwnd] = {
            "cls": cls,
            "title": title,
            "owner": owner,
            "visible": visible,
            "enabled": True,
            "pid": pid,
            "children": kids,
            "top": True,
        }
        return hwnd

    def remove(self, hwnd: int) -> None:
        for child in self.windows[hwnd]["children"]:  # type: ignore[union-attr]
            self.windows.pop(child, None)
        self.windows.pop(hwnd, None)

    # The WindowBackend protocol.
    def top_level_windows(self) -> list[int]:
        return [hwnd for hwnd, window in self.windows.items() if window["top"]]

    def class_name(self, hwnd: int) -> str:
        return str(self.windows[hwnd]["cls"]) if hwnd in self.windows else ""

    def title(self, hwnd: int) -> str:
        return str(self.windows[hwnd]["title"]) if hwnd in self.windows else ""

    def owner(self, hwnd: int) -> int:
        return int(self.windows[hwnd]["owner"]) if hwnd in self.windows else 0  # type: ignore[arg-type]

    def visible(self, hwnd: int) -> bool:
        return bool(self.windows.get(hwnd, {}).get("visible"))

    def enabled(self, hwnd: int) -> bool:
        return bool(self.windows.get(hwnd, {}).get("enabled"))

    def exists(self, hwnd: int) -> bool:
        return hwnd in self.windows

    def pid(self, hwnd: int) -> int:
        return int(self.windows[hwnd]["pid"]) if hwnd in self.windows else 0  # type: ignore[arg-type]

    def descendants(self, hwnd: int) -> list[int]:
        return list(self.windows[hwnd]["children"]) if hwnd in self.windows else []  # type: ignore[arg-type]

    def image_path(self, pid: int) -> str:
        return self.processes.get(pid, ("", None))[0]

    def session(self, pid: int) -> int | None:
        return self.processes.get(pid, ("", None))[1]

    def current_session(self) -> int | None:
        return self.session_id

    def windows_dir(self) -> Path:
        return self.windir

    def _act(self, hwnd: int, behaviour: str) -> None:
        if behaviour == "close" and hwnd in self.windows:
            self.remove(hwnd)
        elif behaviour == "reuse" and hwnd in self.windows:
            self.windows[hwnd]["pid"] = 99999
        elif behaviour == "retitle" and hwnd in self.windows:
            self.windows[hwnd]["title"] = INSTALL + r"\app\helper.exe"

    def click_ok(self, hwnd: int) -> bool:
        if self.raise_on_click is not None:
            raise self.raise_on_click
        self.clicked.append(hwnd)
        self._act(hwnd, self.on_click.get(hwnd, "close"))
        return True

    def post_close(self, hwnd: int) -> bool:
        self.posted.append(hwnd)
        self._act(hwnd, self.on_close.get(hwnd, "ignore"))
        return True

    def now(self) -> float:
        return self.clock

    def sleep(self, seconds: float) -> None:
        self.clock += seconds


@unittest.skipUnless(sys.platform == "win32", "window paths are compared the way Windows compares them")
class MatchRuleTests(unittest.TestCase):
    def judge(self, desktop: FakeWindows, pkg: PackageInfo | None = None) -> list[dialogs.Candidate]:
        return dialogs.candidates(pkg or package(), desktop)

    def only(self, desktop: FakeWindows, pkg: PackageInfo | None = None) -> dialogs.Candidate:
        found = self.judge(desktop, pkg)
        self.assertEqual(len(found), 1, found)
        return found[0]

    def assert_refused_for(self, candidate: dialogs.Candidate, reason: str) -> None:
        self.assertFalse(candidate.matches, candidate)
        self.assertTrue(any(reason in item for item in candidate.reasons), candidate.reasons)

    def test_the_captured_production_dialog_matches(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog()
        candidate = self.only(desktop)
        self.assertTrue(candidate.matches, candidate.reasons)
        self.assertEqual((candidate.hwnd, candidate.pid, candidate.image), (DIALOG, SHELL_PID, SIHOST))

    def test_explorer_may_also_show_it(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(pid=4321)
        self.assertTrue(self.only(desktop).matches)

    def test_a_different_version_folder_of_the_same_package_matches(self) -> None:
        # An update can land while the incident is under way.
        desktop = FakeWindows()
        desktop.add_dialog(title=r"C:\Program Files\WindowsApps\Claude_2.111.0.0_x64__pzs8sxrjxfjjc\app\claude.exe")
        self.assertTrue(self.only(desktop).matches)

    def test_the_executable_compares_without_regard_to_case(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title=INSTALL + r"\APP\CLAUDE.EXE")
        self.assertTrue(self.only(desktop).matches)

    def test_another_programs_dialog_is_not_even_a_candidate(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title="Internet Download Manager 6.43", pid=555)
        self.assertEqual(self.judge(desktop), [])

    def test_another_package_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title=r"C:\Program Files\WindowsApps\Other_1.0.0.0_x64__pzs8sxrjxfjjc\app\claude.exe")
        self.assert_refused_for(self.only(desktop), "does not name a folder of this package")

    def test_another_executable_in_the_package_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title=INSTALL + r"\app\helper.exe")
        self.assert_refused_for(self.only(desktop), "does not name this package's executable")

    def test_a_title_outside_the_install_root_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title=r"D:\Elsewhere\Claude_2.110.0.0_x64__pzs8sxrjxfjjc\app\claude.exe")
        self.assert_refused_for(self.only(desktop), "not a path in the folder Claude is installed under")

    def test_a_title_that_is_not_a_plain_path_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(title=INSTALL + r"\app\..\app\claude.exe")
        self.assert_refused_for(self.only(desktop), "not a plain path")

    def test_an_owner_outside_the_shell_is_refused(self) -> None:
        # A program of the user's own could title a dialog with Claude's path.
        desktop = FakeWindows()
        desktop.add_dialog(pid=555)
        self.assert_refused_for(self.only(desktop), "not shown by the Windows shell")

    def test_a_shell_named_image_in_a_writable_windows_folder_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(pid=666)
        self.assert_refused_for(self.only(desktop), "not shown by the Windows shell")

    def test_a_dialog_in_another_session_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(pid=777)
        self.assert_refused_for(self.only(desktop), "not in the session this tool runs in")

    def test_an_owned_window_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(owner=0x9999)
        self.assert_refused_for(self.only(desktop), "belongs to another window")

    def test_a_hidden_dialog_is_refused(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog(visible=False)
        self.assert_refused_for(self.only(desktop), "not visible")

    def test_a_property_sheet_is_refused(self) -> None:
        # Same window class, no DirectUIHWND. It must never receive WM_USER+102, which a
        # property sheet reads as a request to remove one of its pages.
        desktop = FakeWindows()
        desktop.add_dialog(children=("SysTabControl32", "Button", "Button"))
        self.assert_refused_for(self.only(desktop), "not a task dialog")

    def test_a_dialog_with_no_usable_button_is_refused(self) -> None:
        for kwargs in ({"children": ("DirectUIHWND", "SysLink")}, {"button_enabled": False}, {"button_visible": False}):
            with self.subTest(**{key: str(value) for key, value in kwargs.items()}):
                desktop = FakeWindows()
                desktop.add_dialog(**kwargs)
                self.assert_refused_for(self.only(desktop), "no button to press")

    def test_a_package_with_no_known_executable_matches_nothing(self) -> None:
        desktop = FakeWindows()
        desktop.add_dialog()
        self.assert_refused_for(self.only(desktop, package(executable="")), "names no executable")


@unittest.skipUnless(sys.platform == "win32", "window paths are compared the way Windows compares them")
class DismissalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.desktop = FakeWindows()
        self.reporter = reporting.Reporter()

    def lines(self, state: str) -> list[str]:
        return [line for line in self.reporter.lines if line.startswith(f"[{state}]")]

    def dismiss(self, *, logged: bool | None = True, before: dialogs.Snapshot | None = None) -> int:
        snap = before if before is not None else dialogs.snapshot(package(), self.desktop)
        return dialogs.dismiss_after_green(package(), snap, self.reporter, self.desktop, failure_logged=logged)

    def test_the_ok_button_is_pressed_and_nothing_further_is_sent(self) -> None:
        self.desktop.add_dialog()
        self.assertEqual(self.dismiss(), 1)
        self.assertEqual(self.desktop.clicked, [DIALOG])
        self.assertEqual(self.desktop.posted, [], "WM_CLOSE is not sent once the dialog closed")
        self.assertEqual(len(self.lines("DIALOG")), 1, self.reporter.lines)
        self.assertIn("by TDM_CLICK_BUTTON", self.lines("DIALOG")[0])
        self.assertIn("sihost.exe", self.lines("DIALOG")[0])

    def test_wm_close_is_tried_when_the_button_press_does_not_close_it(self) -> None:
        self.desktop.add_dialog()
        self.desktop.on_click[DIALOG] = "ignore"
        self.desktop.on_close[DIALOG] = "close"
        self.assertEqual(self.dismiss(), 1)
        self.assertEqual((self.desktop.clicked, self.desktop.posted), ([DIALOG], [DIALOG]))
        self.assertIn("by WM_CLOSE", self.lines("DIALOG")[0])

    def test_a_dialog_nothing_closes_is_reported_and_left(self) -> None:
        self.desktop.add_dialog()
        self.desktop.on_click[DIALOG] = "ignore"
        self.assertEqual(self.dismiss(), 0)
        self.assertTrue(self.desktop.exists(DIALOG))
        self.assertTrue(any("still open" in line for line in self.lines("NOTE")), self.reporter.lines)
        self.assertEqual(self.lines("DIALOG"), [])

    def test_a_dialog_that_changes_after_the_button_press_gets_no_wm_close(self) -> None:
        # The same process can reuse the window for something else; it is checked again before
        # the second message, so WM_CLOSE never reaches a window that no longer matches.
        self.desktop.add_dialog()
        self.desktop.on_click[DIALOG] = "retitle"
        self.desktop.on_close[DIALOG] = "close"
        self.assertEqual(self.dismiss(), 0)
        self.assertEqual((self.desktop.clicked, self.desktop.posted), ([DIALOG], []))
        self.assertTrue(self.desktop.exists(DIALOG))
        self.assertEqual(self.lines("DIALOG"), [])
        notes = self.lines("NOTE")
        self.assertEqual(len(notes), 1, self.reporter.lines)
        self.assertIn("changed after TDM_CLICK_BUTTON", notes[0])

    def test_a_handle_reused_by_another_process_counts_as_closed(self) -> None:
        # Once a window is destroyed its handle can be reused; a live handle is not proof.
        self.desktop.add_dialog()
        self.desktop.on_click[DIALOG] = "reuse"
        self.assertEqual(self.dismiss(), 1)
        self.assertEqual(self.desktop.posted, [])

    def test_no_recent_sharing_violation_leaves_the_dialog_open(self) -> None:
        self.desktop.add_dialog()
        self.assertEqual(self.dismiss(logged=False), 0)
        self.assertEqual(self.desktop.clicked, [])
        self.assertTrue(any("left open" in line for line in self.lines("NOTE")), self.reporter.lines)

    def test_the_recent_failure_is_read_from_the_event_log(self) -> None:
        self.desktop.add_dialog()
        with mock.patch.object(dialogs.events, "auto_recovery_events", return_value=[]) as query:
            self.assertEqual(self.dismiss(logged=None), 0)
        query.assert_called_once()
        self.assertEqual(query.call_args.kwargs.get("minutes"), dialogs.RECENT_FAILURE_MINUTES)
        self.assertEqual(self.desktop.clicked, [])
        with mock.patch.object(dialogs.events, "auto_recovery_events", return_value=[{"record_id": 1}]):
            self.assertEqual(self.dismiss(logged=None), 1)

    def test_an_event_log_that_cannot_be_read_leaves_the_dialog_open(self) -> None:
        from clauderestart.errors import RecoveryError

        self.desktop.add_dialog()
        failure = RecoveryError("PowerShell query failed (1): The AppModel event log could not be read: denied")
        with mock.patch.object(dialogs.events, "auto_recovery_events", side_effect=failure):
            self.assertEqual(self.dismiss(logged=None), 0)
        self.assertEqual((self.desktop.clicked, self.desktop.posted), ([], []))
        self.assertTrue(any("could not be closed automatically" in line for line in self.lines("NOTE")))

    def test_a_dialog_that_appeared_after_launch_is_never_closed(self) -> None:
        before = dialogs.snapshot(package(), self.desktop)
        self.desktop.add_dialog()  # raised after the snapshot, so by a click after launch
        self.assertEqual(self.dismiss(before=before), 0)
        self.assertEqual(self.desktop.clicked, [])

    def test_a_handle_reused_before_dismissal_is_not_touched(self) -> None:
        self.desktop.add_dialog()
        before = dialogs.snapshot(package(), self.desktop)
        self.desktop.windows[DIALOG]["pid"] = 4321  # now a different process's window
        self.assertEqual(self.dismiss(before=before), 0)
        self.assertEqual(self.desktop.clicked, [])

    def test_a_dialog_that_changed_after_the_snapshot_is_left_alone(self) -> None:
        self.desktop.add_dialog()
        before = dialogs.snapshot(package(), self.desktop)
        self.desktop.windows[DIALOG]["title"] = INSTALL + r"\app\helper.exe"
        self.assertEqual(self.dismiss(before=before), 0)
        self.assertEqual(self.desktop.clicked, [])
        self.assertTrue(any("changed before it could be closed" in line for line in self.lines("NOTE")))

    def test_a_snapshot_that_failed_is_reported_and_nothing_is_sent(self) -> None:
        self.desktop.add_dialog()
        self.assertEqual(self.dismiss(before=dialogs.Snapshot((), "EnumWindows failed")), 0)
        self.assertEqual(self.desktop.clicked, [])
        self.assertTrue(any("could not run before launch" in line for line in self.lines("NOTE")))

    def test_an_error_while_closing_never_escapes(self) -> None:
        self.desktop.add_dialog()
        self.desktop.raise_on_click = OSError("access denied")
        self.assertEqual(self.dismiss(), 0)
        self.assertTrue(any("could not be closed automatically" in line for line in self.lines("NOTE")))

    def test_every_match_is_closed(self) -> None:
        # Each click on Claude while it was blocked leaves its own dialog.
        self.desktop.add_dialog(DIALOG)
        self.desktop.add_dialog(DIALOG + 1)
        self.assertEqual(self.dismiss(), 2)
        self.assertEqual(sorted(self.desktop.clicked), [DIALOG, DIALOG + 1])

    def test_a_snapshot_never_raises(self) -> None:
        broken = mock.Mock(spec=FakeWindows)
        broken.windows_dir.return_value = Path(r"C:\WINDOWS")
        broken.current_session.return_value = 1
        broken.top_level_windows.side_effect = OSError("EnumWindows failed")
        snap = dialogs.snapshot(package(), broken)
        self.assertEqual(snap.windows, ())
        self.assertIn("EnumWindows failed", snap.error)


class LaunchGateTests(unittest.TestCase):
    """The dialog is closed after GREEN only: VISIBLE could not check for new violations."""

    def launch(self, *, violations: list[dict[str, object]], event_error: Exception | None = None):
        reporter = reporting.Reporter()
        order: list[str] = []
        snap = dialogs.Snapshot((dialogs.Candidate(DIALOG, SHELL_PID, TITLE, SIHOST),))

        def fake_snapshot(_package):
            order.append("snapshot")
            return snap

        def fake_popen(*_args, **_kwargs):
            order.append("launch")
            return mock.Mock(wait=mock.Mock(return_value=0))

        def fake_violations(_package, _since):
            if event_error is not None:
                raise event_error
            return violations

        window = [{"hwnd": 1, "pid": 33116, "title": "Claude", "path": INSTALL + r"\app\Claude.exe"}]
        with mock.patch.object(recovery.dialogs, "snapshot", side_effect=fake_snapshot), mock.patch.object(
            recovery.dialogs, "dismiss_after_green"
        ) as dismiss, mock.patch.object(recovery.subprocess, "Popen", side_effect=fake_popen), mock.patch.object(
            recovery, "visible_claude_windows", return_value=window
        ), mock.patch.object(
            recovery.events, "appmodel_share_violations", side_effect=fake_violations
        ), mock.patch.object(recovery.time, "sleep"):
            result = recovery.launch_and_verify(package(), reporter, 3)
        return result, dismiss, order, snap, reporter

    def test_green_closes_the_dialogs_recorded_before_launch(self) -> None:
        result, dismiss, order, snap, reporter = self.launch(violations=[])
        self.assertTrue(result)
        self.assertEqual(order, ["snapshot", "launch"], "the snapshot is taken before Claude is started")
        dismiss.assert_called_once_with(package(), snap, reporter)

    def test_visible_without_an_event_check_leaves_them_open(self) -> None:
        result, dismiss, _order, _snap, reporter = self.launch(violations=[], event_error=RuntimeError("log unavailable"))
        self.assertTrue(result)
        self.assertTrue(any(line.startswith("[VISIBLE]") for line in reporter.lines), reporter.lines)
        dismiss.assert_not_called()

    def test_red_leaves_them_open(self) -> None:
        result, dismiss, _order, _snap, _reporter = self.launch(violations=[{"Id": 208}])
        self.assertFalse(result)
        dismiss.assert_not_called()


class ListingTests(unittest.TestCase):
    def test_the_listing_reports_each_verdict_and_closes_nothing(self) -> None:
        found = [
            dialogs.Candidate(DIALOG, SHELL_PID, TITLE, SIHOST),
            dialogs.Candidate(0x2, 555, TITLE, PYTHON, ("it is not shown by the Windows shell (python.exe)",)),
        ]
        reporter = reporting.Reporter()
        with mock.patch.object(cli, "get_claude_package", return_value=package()), mock.patch.object(
            cli.dialogs, "candidates", return_value=found
        ), mock.patch.object(dialogs.WindowsWindowBackend, "click_ok") as click, mock.patch.object(
            dialogs.WindowsWindowBackend, "post_close"
        ) as close:
            code = cli.show_error_dialogs(reporter)
        self.assertEqual(code, cli.EXIT_OK)
        text = "\n".join(reporter.lines)
        self.assertIn("recovery would close it once Claude is verified running", text)
        self.assertIn("recovery would leave it open: it is not shown by the Windows shell", text)
        click.assert_not_called()
        close.assert_not_called()

    def test_the_listing_says_so_when_there_is_nothing(self) -> None:
        reporter = reporting.Reporter()
        with mock.patch.object(cli, "get_claude_package", return_value=package()), mock.patch.object(
            cli.dialogs, "candidates", return_value=[]
        ):
            self.assertEqual(cli.show_error_dialogs(reporter), cli.EXIT_OK)
        self.assertIn("No dialog mentioning this Claude package is open", "\n".join(reporter.lines))


if __name__ == "__main__":
    unittest.main()
