# Claude Restart

<img src="assets/ClaudeRestart-256.png" width="96" align="right" alt="Claude Restart icon">

Claude Restart fixes the Claude Desktop for Windows error **Another program is currently using this file** (`0x80070020`). After Claude updates itself, Windows sometimes keeps the old version's process container alive (a kernel Job held by the Application Information service), and the new version cannot start. Claude Restart closes only that verified obsolete Job and opens the installed Claude.

Install automatic recovery once and keep using your normal Claude shortcut, or run the manual launcher whenever Claude fails to open. No Python is required.

## Before you start

- Windows 10 (version 2004 or later) or Windows 11
- Claude Desktop installed as the MSIX package, which is what the installer from claude.ai and the Microsoft Store both provide (package family `Claude_pzs8sxrjxfjjc`)

## Download

1. Open the [latest release](https://github.com/TranDenyDFW/claude-appx-restart/releases/latest).
2. Download `ClaudeRestart-vX.Y.Z-win-x64.zip` and extract it anywhere, for example your Downloads folder. Installing copies what it needs into `C:\Program Files\ClaudeRestart\versions\<version>-<id>`.

The ZIP contains:

| File | Purpose |
|---|---|
| `ClaudeRestart.exe` | The tool. Shows its progress and result in a console window. |
| `ClaudeRestart-quiet.exe` | The same tool without a console window. The scheduled task runs this one, so an automatic recovery is invisible. |
| `Install Automatic Recovery.cmd` | Installs the program into `C:\Program Files\ClaudeRestart` and registers the scheduled task (one UAC prompt). |
| `Start Claude Safely.cmd` | Repairs and starts Claude on demand (one UAC prompt). |
| `Remove Automatic Recovery.cmd` | Removes the scheduled task and the files the installer placed in `C:\Program Files\ClaudeRestart` (one UAC prompt). |
| `ClaudeRestart-launch.cmd` | Shared dispatcher the three launchers call: runs the exe beside it, or the Python source. |

The executables are not code-signed, so Windows SmartScreen may show **Windows protected your PC** the first time. Choose **More info** and then **Run anyway**, or right-click the file, open **Properties**, and tick **Unblock**. `SHA256SUMS.txt` on the release page lists the checksums of every file, for you to check the download; the installer never reads it, because a file sitting beside the executables can be replaced along with them.

## Install automatic recovery

1. Double-click **Install Automatic Recovery.cmd** in the extracted folder.
2. Approve the User Account Control (UAC) prompt.
3. Keep opening Claude from your normal shortcut.

The installer creates a scheduled task named `Claude AppX Auto-Recovery` that runs `ClaudeRestart-quiet.exe` from `C:\Program Files\ClaudeRestart\versions\<version>-<id>`. The task runs with administrator rights, so before it installs anything the tool checks that folder is one only administrators can change, and creates it that way when it is absent. If the folder already exists and any other account can change it, or if anything inside it is a junction, a symbolic link or a file with a second name, the install stops and asks you to delete the folder by hand; it will not repair a folder somebody else can alter while it works. You can delete the extracted folder afterwards.

The windowed executable is checked before it is installed. The console executable you ran carries the exact checksum of its windowed twin, recorded when the release was built, and the twin is opened, hashed and copied through one handle that denies anyone else write or delete access, so the file that was checked is the file that gets installed. A twin that does not match is refused and nothing is changed.

The task fires when Windows records this exact startup failure (AppModel-Runtime Event 208 for Claude with error `0x80070020`), runs only while you are signed in, also runs on battery power, and is limited to one instance and five minutes per run. When the failure occurs, the task closes only the verified obsolete Claude Job and opens the installed version of Claude.

The error dialog can still appear briefly, because Windows records the failure before recovery starts.

To upgrade, extract a newer release and run its **Install Automatic Recovery.cmd**. The new version is written into a new folder and fully checked there; only then does the task start pointing at it, and the previous version is removed afterwards. Nothing is ever written over the files the running task uses, so a failure at any point leaves the previous version and the previous task working. If a recovery is running at that moment, the old version cannot be cleaned up yet and the tool says so; run the installer again later to finish tidying up.

## Start Claude without automatic recovery

Double-click **Start Claude Safely.cmd** and approve the UAC prompt. The launcher checks for an obsolete Claude Job before opening Claude, so the error dialog should not appear.

The launcher prints `GREEN` after it finds a visible Claude window and confirms that Windows recorded no new `0x80070020` errors.

## Remove automatic recovery

Double-click **Remove Automatic Recovery.cmd** and approve the UAC prompt. This removes the scheduled task and the files the installer recorded when it installed them, without changing Claude.

Removal follows that record and nothing else. A file the installer never placed there is kept and reported. A file that was installed but has changed since is also kept, because it is no longer the file that was installed; add `--force-cleanup` to delete those too. The folder itself goes only when it is empty. If you run removal from inside the installed folder, that folder stays, because a program cannot delete itself; delete it afterwards.

## Check the status or recent errors

Open a terminal in `C:\Program Files\ClaudeRestart\versions\<version>-<id>` (or the extracted folder) and run one of these commands. None of them changes anything, and only `--scan` asks for UAC.

```powershell
# Is automatic recovery installed, which file does it run, and how did it last run?
.\ClaudeRestart.exe --automation-status

# Find this Claude startup error in the last 180 minutes
.\ClaudeRestart.exe --trace --minutes 180

# Look for an obsolete Claude Job without closing anything
.\ClaudeRestart.exe --scan

.\ClaudeRestart.exe --version
```

`--automation-status` reports the exact file the task runs, whether that file sits inside the protected folder, whether the folder is still administrator-only, and whether the installed files still match what was installed.

`--scan` also reports, for every Claude Job it finds, whether that Job's membership could be frozen. An obsolete Job exists only while the failure is happening, so this is the way to find out beforehand that a repair would work.

Every run writes `last-run.log` next to the executable that ran, or to `%LOCALAPPDATA%\ClaudeRestart\last-run.log` when that folder is read-only. Automatic recovery therefore logs to `C:\Program Files\ClaudeRestart\versions\<version>-<id>\last-run.log`, while status and trace commands run without administrator rights log to `%LOCALAPPDATA%\ClaudeRestart\last-run.log`. When a run asks for administrator access and the elevated run never starts, the reason is written to the log rather than lost.

Exit codes: `0` success, `1` error, `2` safety stop (nothing was changed), `3` internal error (details in the log), `10` `--scan` or `--trace` found something. A missing or altered `ClaudeRestart-quiet.exe` now exits `2` rather than `1`, because nothing was changed. A scheduled run reports `0` to Task Scheduler for every outcome it handled, so read `last-run.log` for the reason; `3` there means an internal error.

## Run from source instead

The tool is `claude_restart.py` plus the `clauderestart` package folder beside it, which need only [Python 3.10 or newer](https://www.python.org/downloads/windows/) and the standard library. Clone the repository or download the source ZIP; a single downloaded file is not enough.

```powershell
py -3 .\claude_restart.py --automation-status
py -3 .\claude_restart.py --trace --minutes 180
py -3 .\claude_restart.py --install-automation
```

The three `.cmd` launchers call `ClaudeRestart-launch.cmd`, which runs `ClaudeRestart.exe` when it is next to them and falls back to `py -3` or `python.exe` otherwise. Their exit code is the elevated run's real result, because the tool waits for the administrator process it starts. When installed from source, the scheduled task runs `pythonw.exe` so it has no console window. A source install copies nothing into Program Files: the task runs the interpreter and script from where they are, so prefer the release executables unless both live in folders only administrators can change.

## What the tool can close

The tool identifies the installed Claude package, then inspects the Windows Job objects held by the Application Information (`Appinfo`) service. It closes a Job only when its package version is older than the installed Claude version.

Before closing one, it checks every member of that Job twice, freezes the Job so no further process can join it, and checks once more that the members are exactly the ones it verified, including that each is still the same process rather than a reused process number. A Job that gains a member at any point is left alone, and so is a Job whose membership cannot be frozen.

The tool stops without making changes when it finds a current version, another user, another Windows session, a newer version, an unexpected package identity, or an application identity it cannot establish. It does not kill processes by executable name.

Only the `0x80070020` failure triggers automatic recovery. Other Claude launch failures, such as `0x80073D00`, are outside its scope.

For the event fields, trigger rule, and validation details, read [Windows event tracing and automatic recovery](docs/windows-event-automation.md).

## Security notes

- The executables are not code-signed. Their Authenticode status reads `NotSigned`, which is why SmartScreen warns on first run. Check the download against `SHA256SUMS.txt` on the release page, or with `py -3 tools/verify_release.py --tag vX.Y.Z`.
- The installed folder is administrator-only, and the installer verifies that before it installs and again afterwards. A standard user can read and run the installed files but cannot change, rename or delete them.
- The console executable authenticates its windowed twin from a checksum built into it, not from any file on disk, and holds its own file open while it runs so it cannot be swapped underneath itself. What it cannot control is which file is at that path when you approve the UAC prompt: Windows runs whatever is there at that moment.
- A one-file build unpacks its support libraries into a folder under `%TEMP%` that belongs to the account running it. Closing that gap needs code signing plus an installer or a folder-based build, which is why the scheduled task never runs from the download folder in the first place.

## Build from source

```powershell
py -3 build.py
```

`build.py` installs the pinned PyInstaller and Pillow from `requirements-build.txt`, runs the unit tests, regenerates the icon with `tools/make_icon.py`, then builds in two stages: the windowed twin first, then the console executable carrying that twin's checksum. It smoke-tests both, and writes the release ZIP, `SHA256SUMS.txt` and `release-manifest.json` into `dist\`. GitHub Actions runs the same steps on pull requests and on pushes to `main`. Pushing a `v*` tag that matches `__version__` additionally publishes a release from a separate job that never runs repository code and is the only job with write access; see [the release process](docs/release-process.md).
