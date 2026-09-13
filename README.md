# Claude Restart

<img src="assets/ClaudeRestart-256.png" width="96" align="right" alt="Claude Restart icon">

Claude Restart fixes the Claude Desktop for Windows error **Another program is currently using this file** (`0x80070020`). After Claude updates itself, Windows sometimes keeps the old version's process container alive (a kernel Job held by the Application Information service), and the new version cannot start. Claude Restart closes only that verified obsolete Job and opens the installed Claude.

Install automatic recovery once and keep using your normal Claude shortcut, or run the manual launcher whenever Claude fails to open. No Python is required.

## Before you start

- Windows 10 (version 2004 or later) or Windows 11
- Claude Desktop installed as the MSIX package, which is what the installer from claude.ai and the Microsoft Store both provide (package family `Claude_pzs8sxrjxfjjc`)

## Download

1. Open the [latest release](https://github.com/TranDenyDFW/claude-appx-restart/releases/latest).
2. Download `ClaudeRestart-vX.Y.Z-win-x64.zip` and extract it to a permanent folder, for example `C:\Tools\ClaudeRestart`.

The ZIP contains:

| File | Purpose |
|---|---|
| `ClaudeRestart.exe` | The tool. Shows its progress and result in a console window. |
| `ClaudeRestart-quiet.exe` | The same tool without a console window. The scheduled task runs this one, so an automatic recovery is invisible. |
| `Install Automatic Recovery.cmd` | Registers the scheduled task (one UAC prompt). |
| `Start Claude Safely.cmd` | Repairs and starts Claude on demand (one UAC prompt). |
| `Remove Automatic Recovery.cmd` | Removes the scheduled task (one UAC prompt). |
| `ClaudeRestart-launch.cmd` | Shared dispatcher the three launchers call: runs the exe beside it, or the Python source. |

The executables are not code-signed, so Windows SmartScreen may show **Windows protected your PC** the first time. Choose **More info** and then **Run anyway**, or right-click the file, open **Properties**, and tick **Unblock**. `SHA256SUMS.txt` on the release page lists the checksums of every file.

## Install automatic recovery

1. Double-click **Install Automatic Recovery.cmd**.
2. Approve the User Account Control (UAC) prompt.
3. Keep opening Claude from your normal shortcut.

Windows creates a scheduled task named `Claude AppX Auto-Recovery`. It fires when Windows records this exact startup failure (AppModel-Runtime Event 208 for Claude with error `0x80070020`), runs only while you are signed in, also runs on battery power, and is limited to one instance and five minutes per run. When the failure occurs, the task closes only the verified obsolete Claude Job and opens the installed version of Claude.

The error dialog can still appear briefly, because Windows records the failure before recovery starts.

Keep the folder where you extracted the files: the task points at `ClaudeRestart-quiet.exe` in that folder. If you move the folder, run **Install Automatic Recovery.cmd** again.

## Start Claude without automatic recovery

Double-click **Start Claude Safely.cmd** and approve the UAC prompt. The launcher checks for an obsolete Claude Job before opening Claude, so the error dialog should not appear.

The launcher prints `GREEN` after it finds a visible Claude window and confirms that Windows recorded no new `0x80070020` errors.

## Remove automatic recovery

Double-click **Remove Automatic Recovery.cmd** and approve the UAC prompt. This removes the scheduled task without changing Claude.

## Check the status or recent errors

Open a terminal in the folder and run one of these commands. None of them changes anything, and only `--scan` asks for UAC.

```powershell
# Is automatic recovery installed, and how did it last run?
.\ClaudeRestart.exe --automation-status

# Find this Claude startup error in the last 180 minutes
.\ClaudeRestart.exe --trace --minutes 180

# Look for an obsolete Claude Job without closing anything
.\ClaudeRestart.exe --scan

.\ClaudeRestart.exe --version
```

Every run writes `last-run.log` next to the executable, or to `%LOCALAPPDATA%\ClaudeRestart\last-run.log` when that folder is read-only.

Exit codes: `0` success, `1` error, `2` safety stop (nothing was changed), `3` internal error (details in the log), `10` `--scan` or `--trace` found something. A scheduled run reports `0` to Task Scheduler for every outcome it handled, so read `last-run.log` for the reason; `3` there means an internal error.

## Run from source instead

The executables are built from `claude_restart.py`, which needs only [Python 3.10 or newer](https://www.python.org/downloads/windows/) and the standard library:

```powershell
py -3 .\claude_restart.py --automation-status
py -3 .\claude_restart.py --trace --minutes 180
py -3 .\claude_restart.py --install-automation
```

The three `.cmd` launchers call `ClaudeRestart-launch.cmd`, which runs `ClaudeRestart.exe` when it is next to them and falls back to `py -3` or `python.exe` otherwise. Their exit code is the elevated run's real result, because the tool waits for the administrator process it starts. When installed from source, the scheduled task runs `pythonw.exe` so it has no console window.

## What the tool can close

The tool identifies the installed Claude package, then inspects the Windows Job objects held by the Application Information (`Appinfo`) service. It closes a Job only when its package version is older than the installed Claude version.

The tool stops without making changes when it finds a current version, another user, another Windows session, a newer version, or an unexpected package identity. It does not kill processes by executable name.

Only the `0x80070020` failure triggers automatic recovery. Other Claude launch failures, such as `0x80073D00`, are outside its scope.

For the event fields, trigger rule, and validation details, read [Windows event tracing and automatic recovery](docs/windows-event-automation.md).

## Build from source

```powershell
py -3 build.py
```

`build.py` installs the pinned PyInstaller and Pillow from `requirements-build.txt`, runs the unit tests, regenerates the icon with `tools/make_icon.py`, builds both executables from `ClaudeRestart.spec`, smoke-tests them, and writes the release ZIP and `SHA256SUMS.txt` into `dist\`. GitHub Actions runs the same steps on pull requests and on pushes to `main`. Pushing a `v*` tag that matches `__version__` additionally publishes a release from a separate job that never runs repository code and is the only job with write access.
