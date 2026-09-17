#!/usr/bin/env python3
"""Prove the security tests can fail, by removing each behaviour and requiring a red test.

A test suite that stays green when the behaviour it claims to protect is deleted proves
nothing. Every entry below is a behaviour this project's security claims rest on, and every
one of them once survived deletion with the whole suite green. Each is applied to a throwaway
copy of the tree; the named test files must turn red.

A mutation whose text no longer matches is reported and fails the run. That is deliberate:
after a refactor the guard must be updated rather than silently passing on a mutation it can
no longer apply.

    py -3 tools/mutation_guard.py
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(".git", "tmp", "dist", "build", ".venv-build", "__pycache__", ".md")

INSTALL_TESTS = ("tests.test_install_transaction", "tests.test_remove")

# (label, file, exact text to remove or weaken, replacement, test modules that must turn red)
MUTATIONS: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    (
        "the twin digest comparison",
        "clauderestart/twin.py",
        "if observed != record.sha256 or size != record.size:",
        "if size != record.size:",
        ("tests.test_twin",),
    ),
    (
        "the membership growth guard during validation",
        "clauderestart/recovery.py",
        """    added = recheck - snapshot
    if added:
        raise SafetyStop(
            f"Refusing to terminate {job.name}: it gained member(s) {sorted(added)} while they were being "
            "checked, so they were never verified."
        )""",
        "    added = recheck - snapshot",
        ("tests.test_recovery_race",),
    ),
    (
        "the Path import the frozen install path needs",
        "clauderestart/cli.py",
        "import os\nfrom pathlib import Path\nimport subprocess",
        "import os\nimport subprocess",
        ("tests.test_twin",),
    ),
    (
        "the check that the registered task runs the installed executable",
        "clauderestart/task.py",
        """    registered = task_command_path(status.get("Execute"))
    if winapi.canonical(registered) != winapi.canonical(executable):
        problems.append(f"the task runs {registered}, expected {executable}")
    return problems""",
        "    return problems",
        ("tests.test_task_xml",),
    ),
    (
        "the build stage guard digest comparison",
        "build.py",
        "    if digest != record.sha256 or size != record.size:",
        "    if size != record.size:",
        ("tests.test_build",),
    ),
    (
        "the build stage guard refusing an absent twin",
        "build.py",
        """    if not built.is_file():
        sys.exit(
            f"The console stage has no windowed twin at {built} to check its record against, so the "
            "record cannot be trusted. Run: py -3 build.py"
        )""",
        "    if not built.is_file():\n        return record",
        ("tests.test_build",),
    ),
    (
        "the manifest comparing the digest of an installed file",
        "clauderestart/install.py",
        '            if observed != digest or observed_size != size:\n'
        '                problems.append(f"{relative} does not match what was installed")',
        '            if observed_size != size:\n'
        '                problems.append(f"{relative} does not match what was installed")',
        INSTALL_TESTS,
    ),
    (
        "refusing a staged file that is not part of the release",
        "clauderestart/install.py",
        '        if relative not in recorded:\n'
        '            raise SafetyStop(f"{path} appeared in the staged files but is not part of this release.")',
        '        if False:\n'
        '            raise SafetyStop(f"{path} appeared in the staged files but is not part of this release.")',
        INSTALL_TESTS,
    ),
    (
        "tying the staged twin to the authenticated record",
        "clauderestart/install.py",
        '            if relative == payload.QUIET_EXE_NAME and digest != twin_sha:\n'
        '                raise SafetyStop("The staged windowed executable is not the one this build was made with.")',
        '            if False:\n'
        '                raise SafetyStop("The staged windowed executable is not the one this build was made with.")',
        INSTALL_TESTS,
    ),
    (
        "acting on the committed manifest verdict",
        "clauderestart/install.py",
        '    problems = manifest.verify(final)\n'
        '    if problems:\n'
        '        raise SafetyStop(f"The installed files in {final} did not verify: " + "; ".join(problems))',
        '    problems = manifest.verify(final)\n'
        '    if False:\n'
        '        raise SafetyStop(f"The installed files in {final} did not verify: " + "; ".join(problems))',
        INSTALL_TESTS,
    ),
    (
        "rehashing the committed twin against the record",
        "clauderestart/install.py",
        '    if digest.hexdigest() != twin_sha:\n'
        '        raise SafetyStop(f"The installed windowed executable in {final} is not the authenticated one.")',
        '    if False:\n'
        '        raise SafetyStop(f"The installed windowed executable in {final} is not the authenticated one.")',
        INSTALL_TESTS,
    ),
    (
        "requiring a trusted owner on an installer owned folder",
        "clauderestart/security.py",
        # The leading newline keeps this from also matching verify_child's deeper indented copy.
        "\n    if info.owner not in TRUSTED_OWNERS:",
        "\n    if False:",
        ("tests.test_security",),
    ),
    (
        "requiring the permission list to be protected from inheritance",
        "clauderestart/security.py",
        "    elif not inherited and not info.control & winapi.SE_DACL_PROTECTED:",
        "    elif False:",
        ("tests.test_security",),
    ),
    (
        "discarding the staged payload when the commit rename fails",
        "clauderestart/install.py",
        """    try:
        _commit_staging(staging, final, reporter)
    except BaseException:
        # Otherwise the error says nothing was changed while the whole payload sits in
        # Program Files under a staging name.
        _discard(staging)
        raise""",
        "    _commit_staging(staging, final, reporter)",
        INSTALL_TESTS,
    ),
    (
        "comparing the registered task's file by handle identity, not only by name",
        "clauderestart/install.py",
        """                if not os.path.samestat(check.stat(), locked.stat()):
                    problems.append("the registered task runs a different file from the one installed")""",
        """                if False:
                    problems.append("the registered task runs a different file from the one installed")""",
        INSTALL_TESTS,
    ),
    (
        "rechecking the whole asset set immediately before publishing",
        ".github/workflows/build.yml",
        """          verify_assets "$release_id"
          peel_tag
          gh api -X PATCH""",
        """          peel_tag
          gh api -X PATCH""",
        ("tests.test_release_workflow",),
    ),
    (
        "rechecking the tag immediately before publishing",
        ".github/workflows/build.yml",
        """          verify_assets "$release_id"
          peel_tag
          gh api -X PATCH""",
        """          verify_assets "$release_id"
          gh api -X PATCH""",
        ("tests.test_release_workflow",),
    ),
    (
        "treating an inherit-only creator-owner entry as repairable rather than blocking",
        "clauderestart/security.py",
        """            seed_only = ace.sid == SID_CREATOR_OWNER and ace.flags & winapi.INHERIT_ONLY_ACE
            if not seed_only:
                blocking.append(message)""",
        "            blocking.append(message)",
        ("tests.test_security",),
    ),
    (
        'refusing a staged file that is a reparse point',
        'clauderestart/install.py',
        '            if locked.is_reparse_point():\n                raise SafetyStop(f"{relative} in {staging} is a reparse point.")',
        '            if False:\n                raise SafetyStop("unused")',
        INSTALL_TESTS,
    ),
    (
        'refusing a staged file that resolves outside the staged folder',
        'clauderestart/install.py',
        '            if not locked.final_path().startswith(winapi.canonical(staging)):\n                raise SafetyStop(f"{relative} in {staging} resolves outside the staged folder.")',
        '            if False:\n                raise SafetyStop("unused")',
        INSTALL_TESTS,
    ),
    (
        'refusing a staged file whose permissions are not what was applied',
        'clauderestart/install.py',
        '            report = backend.verify_child(locked)\n            if not report.ok:\n                raise SafetyStop(f"{relative} in {staging} has unexpected permissions: " + "; ".join(report.problems))',
        '            report = backend.verify_child(locked)',
        INSTALL_TESTS,
    ),
    (
        'the release manifest agreeing with the checksum file',
        '.github/workflows/build.yml',
        '              if assets[name]["sha256"] != digest:\n                  sys.exit(f"SHA256SUMS.txt and the manifest disagree about {name}")',
        '              if False:\n                  sys.exit("unused")',
        ("tests.test_release_workflow",),
    ),
    (
        'the committed folder resolving to itself after the rename',
        'clauderestart/install.py',
        '        if directory.is_reparse_point() or directory.final_path() != winapi.canonical(final):\n            raise SafetyStop(f"{final} did not resolve to itself after it was put in place.")',
        '        if False:\n            raise SafetyStop("unused")',
        INSTALL_TESTS,
    ),
    (
        'the committed executable resolving to itself after the rename',
        'clauderestart/install.py',
        '    if locked.is_reparse_point() or locked.final_path() != winapi.canonical(final / payload.QUIET_EXE_NAME):\n        raise SafetyStop(f"{final} did not resolve to itself after it was put in place.")',
        '    if False:\n        raise SafetyStop("unused")',
        INSTALL_TESTS,
    ),
    (
        'refusing a folder that has no permission list at all',
        'clauderestart/security.py',
        '    if not info.control & winapi.SE_DACL_PRESENT:\n        message = "the folder has no permission list"\n        problems.append(message)\n        blocking.append(message)',
        '    if False:\n        message = "unused"',
        ("tests.test_security",),
    ),
    (
        'refusing a folder that is itself a reparse point',
        'clauderestart/security.py',
        '        if locked.is_reparse_point():\n            return [f"{folder} is a junction, symbolic link, or other reparse point"]',
        '        if False:\n            return ["unused"]',
        ("tests.test_security",),
    ),
    (
        'refusing a folder that does not resolve to itself',
        'clauderestart/security.py',
        '        if winapi.canonical(folder) != locked.final_path():\n            return [f"{folder} does not resolve to itself ({locked.final_path()})"]',
        '        if False:\n            return ["unused"]',
        ("tests.test_security",),
    ),
    (
        'the manifest describing the checksum file that was built',
        '.github/workflows/build.yml',
        '          if assets["SHA256SUMS.txt"]["sha256"] != observed:\n              sys.exit("the manifest does not describe the SHA256SUMS.txt that was built")',
        '          if False:\n              sys.exit("unused")',
        ("tests.test_release_workflow",),
    ),
    (
        'the manifest adding exactly the checksum file',
        '.github/workflows/build.yml',
        '          extra = set(assets) - set(sums)\n          if extra != {"SHA256SUMS.txt"}:\n              sys.exit(f"the manifest must add exactly SHA256SUMS.txt, it adds {sorted(extra)}")',
        '          extra = set(assets) - set(sums)',
        ("tests.test_release_workflow",),
    ),
    (
        "matching the error dialog title to this package's install folder",
        'clauderestart/dialogs.py',
        '    if not separator or not rules.folder_pattern.match(folder):\n',
        '    if not separator:\n',
        ("tests.test_dialogs",),
    ),
    (
        "matching the error dialog title to this package's executable",
        'clauderestart/dialogs.py',
        '    if remainder != os.path.normcase(os.path.normpath(package.application_executable)):\n',
        '    if False:\n',
        ("tests.test_dialogs",),
    ),
    (
        'requiring the error dialog to be shown by the Windows shell',
        'clauderestart/dialogs.py',
        '    if not image or os.path.normcase(image) not in rules.allowed_owners:\n',
        '    if not image:\n',
        ("tests.test_dialogs",),
    ),
    (
        'requiring the error dialog to be a task dialog before WM_USER+102 is sent',
        'clauderestart/dialogs.py',
        '    if not any(name == TASK_DIALOG_SURFACE for _child, name in classes):\n',
        '    if False:\n',
        ("tests.test_dialogs",),
    ),
    (
        "requiring the error dialog to be in this user's session",
        'clauderestart/dialogs.py',
        '    if rules.session is None or backend.session(pid) != rules.session:\n',
        '    if False:\n',
        ("tests.test_dialogs",),
    ),
    (
        'requiring a logged sharing violation before closing the error dialog',
        'clauderestart/dialogs.py',
        '        if not logged:\n',
        '        if False:\n',
        ("tests.test_dialogs",),
    ),
    (
        'closing only a dialog that is still the window recorded before launch',
        'clauderestart/dialogs.py',
        '    if not _still_the_same(window, rules, backend):\n        if _closed(window, backend):\n',
        '    if False:\n        if _closed(window, backend):\n',
        ("tests.test_dialogs",),
    ),
    (
        'counting the error dialog closed only when it is gone',
        'clauderestart/dialogs.py',
        '    return not backend.exists(window.hwnd) or backend.pid(window.hwnd) != window.pid\n',
        '    return True\n',
        ("tests.test_dialogs",),
    ),
    (
        'counting a window handle reused by another process as closed',
        'clauderestart/dialogs.py',
        '    return not backend.exists(window.hwnd) or backend.pid(window.hwnd) != window.pid\n',
        '    return not backend.exists(window.hwnd)\n',
        ("tests.test_dialogs",),
    ),
    (
        'closing the error dialog only after GREEN, never after VISIBLE',
        'clauderestart/recovery.py',
        '    else:\n        reporter.emit(\n            "VISIBLE",\n',
        '    else:\n        dialogs.dismiss_after_green(package, before_launch, reporter)\n        reporter.emit(\n            "VISIBLE",\n',
        ("tests.test_dialogs",),
    ),
    (
        "pressing the task dialog's OK button rather than asking it to close",
        'clauderestart/dialogs.py',
        '            winapi.TDM_CLICK_BUTTON,\n',
        '            winapi.WM_CLOSE,\n',
        ("tests.test_dialogs_windows",),
    ),
    (
        "checking the dialog again before WM_CLOSE is sent",
        'clauderestart/dialogs.py',
        '            return 1\n        if not _still_the_same(window, rules, backend):\n',
        '            return 1\n        if False:\n',
        ("tests.test_dialogs",),
    ),
    (
        "reporting a task lookup that failed as an error rather than as an absent task",
        "clauderestart/task.py",
        "    if ($_.FullyQualifiedErrorId -like '{TASK_NOT_FOUND_ERROR},*') {{",
        "    if ($true) {{",
        ("tests.test_task_xml",),
    ),
    (
        "reading only the not-found error id, not its category, as an absent task",
        "clauderestart/task.py",
        "    if ($_.FullyQualifiedErrorId -like '{TASK_NOT_FOUND_ERROR},*') {{",
        "    if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {{",
        ("tests.test_task_xml",),
    ),
    (
        "reporting an event log that could not be read as an error rather than as no events",
        "clauderestart/events.py",
        "    if ($failures.Count -gt 0) {{",
        "    if ($false) {{",
        ("tests.test_events",),
    ),
    (
        "reading only the no-events error id, not its category, as no events",
        "clauderestart/events.py",
        "$_.FullyQualifiedErrorId -notlike '{NO_EVENTS_ERROR},*'",
        "$_.CategoryInfo.Category -ne 'ObjectNotFound'",
        ("tests.test_events",),
    ),
    (
        "reporting a disabled event log as an error rather than as no events",
        "clauderestart/events.py",
        "    if (-not $log.IsEnabled) {{",
        "    if ($false) {{",
        ("tests.test_events",),
    ),
    (
        "keeping the records that were read when another record could not be",
        "clauderestart/events.py",
        "    if ($found.Count -gt 0) {{\n        return $found\n    }}\n",
        "",
        ("tests.test_events",),
    ),
    (
        "asking Task Scheduler before the install root is created or repaired",
        "clauderestart/install.py",
        "    before = tasks.automation_task_status()\n    root = verify_root(reporter, backend, root)\n",
        "    root = verify_root(reporter, backend, root)\n    before = tasks.automation_task_status()\n",
        ("tests.test_install_transaction",),
    ),
    (
        "checking that the rollback delete of a new task succeeded",
        "clauderestart/install.py",
        "            if completed.returncode == 0:\n",
        "            if True:\n",
        ("tests.test_install_transaction",),
    ),
    (
        "treating a failed delete as done only once the task is confirmed absent",
        "clauderestart/install.py",
        "            if not absent:\n                raise RecoveryError(failed)\n",
        "            if False:\n                raise RecoveryError(failed)\n",
        ("tests.test_install_transaction",),
    ),
    (
        "accepting a failed delete of a task that was never registered as a completed rollback",
        "clauderestart/install.py",
        '                absent = tasks.automation_task_status().get("Installed") is False\n',
        "                absent = False\n",
        ("tests.test_install_transaction",),
    ),
    (
        "refusing to read a failed release lookup as no published release",
        ".github/workflows/build.yml",
        '            elif grep -q "(HTTP 404)" "$WORK/published.err"; then',
        "            elif true; then",
        ("tests.test_release_workflow",),
    ),
    (
        "discarding the 404 response body so it is not read as a published release",
        ".github/workflows/build.yml",
        '              published=""\n',
        "              :\n",
        ("tests.test_release_workflow",),
    ),
    (
        "refusing to read a failed release lookup as unpublished before tagging",
        "tools/release_preflight.py",
        '    elif "(HTTP 404)" in err:',
        "    elif True:",
        ("tests.test_release_preflight",),
    ),
    (
        "writing the checksum file with Unix line endings",
        "build.py",
        '    target.write_text("\\n".join(lines) + "\\n", encoding="utf-8", newline="\\n")',
        '    target.write_text("\\n".join(lines) + "\\n", encoding="utf-8")',
        ("tests.test_build",),
    ),
]


def run(subject: Path, modules: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "unittest", *modules],
        cwd=str(subject),
        capture_output=True,
        text=True,
    )


def main() -> int:
    # --match TEXT runs only the entries whose label contains TEXT, for proving new entries
    # quickly while developing. Continuous integration always runs every entry.
    selected = MUTATIONS
    if "--match" in sys.argv:
        needle = sys.argv[sys.argv.index("--match") + 1].lower()
        selected = [entry for entry in MUTATIONS if needle in entry[0].lower()]
        if not selected:
            print(f"no entry label contains {needle!r}", file=sys.stderr)
            return 1
    survivors: list[str] = []
    for label, relative, old, new, modules in selected:
        with tempfile.TemporaryDirectory() as work:
            subject = Path(work) / "subject"
            shutil.copytree(ROOT, subject, ignore=IGNORE)

            target = subject / relative
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"STALE    {label}: the text matched {text.count(old)} time(s), expected 1")
                survivors.append(label)
                continue

            baseline = run(subject, modules)
            if baseline.returncode != 0:
                print(f"BROKEN   {label}: the tests already fail unmutated, so the result means nothing")
                survivors.append(label)
                continue

            target.write_text(text.replace(old, new), encoding="utf-8")
            mutated = run(subject, modules)
            if mutated.returncode == 0:
                print(f"SURVIVED {label}: the tests stayed green with the behaviour removed")
                survivors.append(label)
            else:
                summary = [line for line in mutated.stderr.splitlines() if line.strip()][-1]
                print(f"CAUGHT   {label} ({summary})")

    caught = len(selected) - len(survivors)
    print(f"\n{caught}/{len(selected)} mutation(s) caught")
    if survivors:
        print("\nThese behaviours can be removed without any test noticing:", file=sys.stderr)
        for label in survivors:
            print(f"  {label}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
