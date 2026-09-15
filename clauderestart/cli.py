"""Command-line entry: argument parsing, the commands, and exit codes."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback

from . import __version__, events, install, payload, recovery, task, twin, winapi
from .elevation import enable_debug_privilege, relaunch_elevated
from .errors import RecoveryError, SafetyStop
from .package import AUTO_RECOVERY_APPLICATION, get_claude_package, trigger_identity_problem
from .reporting import Reporter, app_location


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SAFETY_STOP = 2
EXIT_INTERNAL_ERROR = 3
EXIT_STALE_FOUND = 10


def install_auto_recovery(reporter: Reporter, args: argparse.Namespace | None = None) -> None:
    """Install automatic recovery: a new immutable version, then the task pointing at it."""
    allow_downgrade = bool(getattr(args, "allow_downgrade", False))
    package = get_claude_package()
    problem = trigger_identity_problem(package)
    if problem:
        raise SafetyStop(problem + " Automation was not installed.")
    if not winapi.is_frozen():
        install.install_from_source(reporter, package)
        return
    authenticated = twin.authenticate_twin(Path(sys.executable).resolve())
    try:
        install.install_versioned(reporter, authenticated, package, allow_downgrade=allow_downgrade)
    finally:
        authenticated.close()


def remove_auto_recovery(reporter: Reporter, args: argparse.Namespace | None = None) -> None:
    force = bool(getattr(args, "force_cleanup", False))
    status = task.automation_task_status()
    if status.get("Installed"):
        completed = task.delete_task()
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RecoveryError(f"Could not remove {task.AUTO_RECOVERY_TASK_NAME}: {detail}")
        reporter.emit("REMOVED", f"Task '{task.AUTO_RECOVERY_TASK_NAME}' was removed.")
    else:
        reporter.emit("NOT INSTALLED", f"Task '{task.AUTO_RECOVERY_TASK_NAME}' is already absent.")
    if winapi.is_frozen():
        install.remove_installation(reporter, force=force)


def show_auto_recovery_status(reporter: Reporter) -> int:
    status = task.automation_task_status()
    if not status.get("Installed"):
        reporter.emit("NOT INSTALLED", f"Task '{task.AUTO_RECOVERY_TASK_NAME}' is absent.")
        return EXIT_ERROR
    reporter.emit(
        "AUTOMATION",
        f"State={status.get('State')}; run level={status.get('RunLevel')}; "
        f"logon={status.get('LogonType')}; instances={status.get('MultipleInstances')}.",
    )
    reporter.emit("ACTION", f"{status.get('Execute')} {status.get('Arguments')}")
    starts_on_battery = "yes" if status.get("DisallowStartIfOnBatteries") is False else "no"
    survives_unplug = "yes" if status.get("StopIfGoingOnBatteries") is False else "no"
    reporter.emit(
        "SETTINGS",
        f"starts on battery={starts_on_battery}; keeps running when unplugged={survives_unplug}; "
        f"time limit={status.get('ExecutionTimeLimit') or 'default'}; priority={status.get('Priority')}.",
    )
    if status.get("Description"):
        reporter.emit("DESCRIPTION", str(status.get("Description")))
    reporter.emit("LAST RUN", f"{status.get('LastRunTime') or 'never'}; result={status.get('LastTaskResult')}")
    registered = task.task_command_path(status.get("Execute"))
    try:
        root = install.install_dir()
        under = "under the protected folder" if os.path.normcase(str(registered)).startswith(
            os.path.normcase(str(root)) + os.sep
        ) else "not under the protected folder"
        reporter.emit("EXECUTABLE", f"{registered} ({under})")
        install.installed_state(reporter, root)
    except (RecoveryError, OSError) as exc:
        reporter.emit("EXECUTABLE", f"{registered} (the protected folder could not be read: {exc})")
    return EXIT_OK


def trace_auto_recovery_events(reporter: Reporter, minutes: int) -> int:
    package = get_claude_package()
    found = events.auto_recovery_events(package, minutes=minutes)
    if not found:
        reporter.emit(
            "TRACE CLEAR",
            f"No structured Claude {events.SHARE_VIOLATION_HEX} launch failures in the last {minutes} minute(s).",
        )
        return EXIT_OK
    reporter.emit(
        "TRACE RED",
        f"Windows recorded {len(found)} structured Claude {events.SHARE_VIOLATION_HEX} launch failure(s) "
        f"in the last {minutes} minute(s).",
    )
    for event in found[:20]:
        reporter.emit(
            "EVENT",
            f"Record {event['record_id']} at {event['time_created']}: Event 208, "
            f"{event['application_name']}, error {event['error_code']}.",
        )
    return EXIT_STALE_FOUND


def run(args: argparse.Namespace, reporter: Reporter) -> int:
    package = get_claude_package()
    reporter.emit("PACKAGE", f"Installed: {package.package_full_name}")
    problem = trigger_identity_problem(package)
    if problem:
        reporter.emit("WARN", problem)
    if package.application_id is None and not args.scan:
        # Fail closed before anything is terminated: without a confirmed identity the
        # tool could kill the stale Job and then be unable to start Claude again.
        raise SafetyStop(
            f"Claude application id unknown ({package.application_id_error}); "
            "no Job was terminated and Claude was not launched."
        )
    if args.event_triggered:
        found = events.auto_recovery_events(package, minutes=10)
        if not found:
            reporter.emit(
                "NO ACTION",
                "Scheduled invocation had no matching current-package Event 208 in the last 10 minutes.",
            )
            return EXIT_OK
        newest = found[0]
        reporter.emit(
            "TRIGGER",
            f"Validated Windows Event record {newest['record_id']} at {newest['time_created']}.",
        )
    appinfo_pid = recovery.get_appinfo_pid()
    if not appinfo_pid:
        reporter.emit("SCAN", "Appinfo is stopped, so it cannot currently retain a stale Claude Job.")
        if args.scan:
            return EXIT_OK
        if args.event_triggered:
            reporter.emit(
                "NO ACTION",
                "The event matched, but Appinfo is stopped; automatic relaunch was suppressed.",
            )
            return EXIT_OK
        return EXIT_OK if recovery.launch_and_verify(package, reporter, args.wait) else EXIT_ERROR

    reporter.emit("SCAN", f"Inspecting Windows Job handles held by Appinfo PID {appinfo_pid}.")
    jobs = recovery.discover_claude_jobs(appinfo_pid)
    try:
        stale, current = recovery.classify_jobs(package, jobs)
        for job in current:
            reporter.emit(
                "CURRENT",
                f"Leaving current-version Job untouched: {job.name} ({len(job.pids)} member(s)).",
            )
        for job in stale:
            reporter.emit("STALE", f"Verified older Job: {job.name} ({len(job.pids)} member(s)).")
            for info in recovery.process_details(job.pids):
                command = " ".join(info.command_line.split())
                detail = command or info.path or info.name
                reporter.emit("MEMBER", f"PID {info.pid}: {detail}")

        if not stale:
            reporter.emit("SAFE", "No exact older Claude AppX Job is present.")
        if args.scan:
            # A stale Job exists only during an incident, so the freeze is probed on
            # every Claude Job here: that answers "would a repair work" beforehand.
            for label, job in [("CURRENT", job) for job in current] + [("STALE", job) for job in stale]:
                probe = recovery.probe_freeze(job)
                state = "available" if probe["available"] else f"unavailable ({probe['error']})"
                reporter.emit(
                    "FREEZE",
                    f"{label} {job.name}: membership freeze {state}; "
                    f"active members {probe['active']}; current limit {probe['limit']}.",
                )
            reporter.emit("DRY-RUN", "No processes were terminated and Claude was not launched.")
            return EXIT_STALE_FOUND if stale else EXIT_OK
        if args.event_triggered and not stale:
            reporter.emit(
                "NO ACTION",
                "The event matched, but no exact older Claude Job exists; automatic relaunch was suppressed.",
            )
            return EXIT_OK
        if stale and not args.yes:
            if not _stdin_is_interactive():
                raise SafetyStop("Confirmation is required; rerun interactively or pass --yes.")
            answer = input("Type REPAIR to terminate only the verified stale Job member(s): ").strip()
            if answer != "REPAIR":
                reporter.emit("CANCELLED", "No processes were terminated.")
                return EXIT_SAFETY_STOP

        for job in stale:
            # One driver owns validation, the membership freeze, the final re-check and
            # the termination, and reports each step.
            recovery.repair_stale_job(job, appinfo_pid, reporter)
    finally:
        recovery.close_job_records(jobs)

    if stale:
        time.sleep(0.5)
    return EXIT_OK if recovery.launch_and_verify(package, reporter, args.wait) else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repair the verified stale Claude AppX Job failure and start Claude Desktop."
    )
    parser.add_argument("--version", action="version", version=f"ClaudeRestart {__version__}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--scan",
        action="store_true",
        help="read-only scan; exit 10 when an exact stale Job is found",
    )
    mode.add_argument(
        "--trace",
        action="store_true",
        help="read the structured Windows events for this exact launch failure",
    )
    mode.add_argument(
        "--install-automation",
        action="store_true",
        help="install the event-triggered automatic recovery task",
    )
    mode.add_argument(
        "--remove-automation",
        action="store_true",
        help="remove the event-triggered automatic recovery task",
    )
    mode.add_argument(
        "--automation-status",
        action="store_true",
        help="show the automatic recovery task status",
    )
    mode.add_argument(
        "--self-check",
        action="store_true",
        help="validate the historical version-selection invariant without elevation",
    )
    mode.add_argument("--event-triggered", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--print-embedded-twin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--yes", action="store_true", help="skip the typed REPAIR confirmation")
    parser.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="install this version even when a newer one is already registered",
    )
    parser.add_argument(
        "--force-cleanup",
        action="store_true",
        help="when removing, also delete installed files that were changed after installation",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=20,
        metavar="SECONDS",
        help="seconds to wait for a visible Claude window (default: 20)",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        default=180,
        metavar="MINUTES",
        help="lookback window for --trace (default: 180)",
    )
    parser.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-elevate", action="store_true", help=argparse.SUPPRESS)
    return parser


def _stdin_is_interactive() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _pause() -> None:
    if sys.stdin is None or sys.stdout is None:
        return
    try:
        input("Press Enter to close...")
    except (EOFError, RuntimeError, OSError, ValueError):
        pass


def event_triggered_exit_code(exit_code: int) -> int:
    """Map handled outcomes to 0 for Task Scheduler.

    Task Scheduler renders small exit codes as Win32 errors (2 reads as "file not
    found"), so an event-triggered run reports 0 for every outcome it handled and
    explained in last-run.log; only an internal error stays non-zero.
    """
    return EXIT_INTERNAL_ERROR if exit_code == EXIT_INTERNAL_ERROR else EXIT_OK


def print_embedded_twin(reporter: Reporter) -> int:
    """Print the twin record built into this executable (used by the build smoke test)."""
    record = twin.load_embedded_twin()
    if record is None:
        reporter.emit("EMBEDDED TWIN", "none")
        return EXIT_ERROR
    reporter.emit("EMBEDDED TWIN", f"{record.name} {record.sha256} {record.size} {record.version}")
    return EXIT_OK


def main() -> int:
    reporter = Reporter()
    args: argparse.Namespace | None = None
    exit_code = EXIT_ERROR
    try:
        winapi.require_windows()
        winapi.configure()
        # Before anything else, including argument parsing and any lazy import, hold this
        # executable open so it cannot be renamed and replaced while the process runs.
        twin.lock_console()
        args = build_parser().parse_args()
        if args.wait < 3 or args.wait > 120:
            raise RecoveryError("--wait must be between 3 and 120 seconds.")
        if args.print_embedded_twin:
            exit_code = print_embedded_twin(reporter)
        elif args.self_check:
            exit_code = EXIT_OK if recovery.historical_self_check(reporter) else EXIT_ERROR
        elif args.trace:
            exit_code = trace_auto_recovery_events(reporter, args.minutes)
        elif args.automation_status:
            exit_code = show_auto_recovery_status(reporter)
        elif args.event_triggered and not winapi.is_admin():
            raise RecoveryError(
                "The scheduled task is not running elevated; reinstall automatic recovery "
                "from an administrator account."
            )
        elif not winapi.is_admin() and not args.no_elevate:
            if args.elevated:
                raise RecoveryError("Elevation completed without an administrator token.")
            reporter.emit("UAC", "Requesting administrator access to inspect Appinfo's Job handles.")
            # The parent keeps its own log until the child proves it wrote one, so a
            # cancelled prompt or a failed launch still explains itself on disk.
            exit_code = relaunch_elevated(reporter)
            if not reporter.persist:
                reporter.emit("ELEVATED", f"The administrator run finished with exit code {exit_code}; see last-run.log.")
        elif not winapi.is_admin():
            raise RecoveryError("Administrator access is required to inspect Appinfo's Job handles.")
        elif args.install_automation:
            install_auto_recovery(reporter, args)
            exit_code = EXIT_OK
        elif args.remove_automation:
            remove_auto_recovery(reporter, args)
            exit_code = EXIT_OK
        else:
            enable_debug_privilege()
            exit_code = run(args, reporter)
    except SafetyStop as exc:
        reporter.emit("SAFETY STOP", str(exc))
        exit_code = EXIT_SAFETY_STOP
    except (RecoveryError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        reporter.emit("ERROR", str(exc))
        exit_code = EXIT_ERROR
    except Exception:  # noqa: BLE001 - last resort so the failure reaches last-run.log
        reporter.emit("INTERNAL ERROR", traceback.format_exc().strip())
        exit_code = EXIT_INTERNAL_ERROR
    finally:
        try:
            log_path = reporter.save(guard=reporter.log_guard) if reporter.persist else None
            if log_path is not None and sys.stdout is not None:
                print(f"[LOG] {log_path}", flush=True)
        except OSError as exc:
            if sys.stderr is not None:
                print(f"[LOG ERROR] {exc}", file=sys.stderr, flush=True)
        if args is not None and args.pause and (winapi.is_admin() or args.self_check or args.no_elevate):
            _pause()
    if args is not None and args.event_triggered:
        return event_triggered_exit_code(exit_code)
    return exit_code
