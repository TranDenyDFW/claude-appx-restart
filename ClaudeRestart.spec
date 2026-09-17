# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for claude-appx-restart.

One invocation builds ONE executable, chosen by the CLAUDERESTART_BUILD_TARGET
environment variable:

- quiet    ClaudeRestart-quiet.exe  windowed build; registered as the scheduled task
                                    action so an automatic recovery never shows a
                                    console window (the pythonw.exe equivalent)
- console  ClaudeRestart.exe        console build; used by the .cmd launchers and for
                                    manual runs. It is the trust root for the windowed
                                    twin, so it embeds that twin's SHA-256 and must be
                                    built after it.

The stages must therefore run in order, which is what build.py does. Running this spec
by hand is not supported and stops with a message.

Run: py -3 build.py
"""

import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(SPECPATH)
SOURCE = ROOT / "claude_restart.py"
TARGET = os.environ.get("CLAUDERESTART_BUILD_TARGET", "")

# build.py owns version parsing, the payload, and the twin record; load it by path so
# the module name cannot collide.
_build_spec = importlib.util.spec_from_file_location("claude_restart_build", ROOT / "build.py")
_build = importlib.util.module_from_spec(_build_spec)
# Register before executing: a by-path load leaves sys.modules empty, and anything that
# resolves types through it (dataclasses, typing) then fails inside build.py.
sys.modules[_build_spec.name] = _build
_build_spec.loader.exec_module(_build)
VERSION = _build.read_version()
# Stops the build when the stage and the generated twin record do not match.
TWIN_RECORD = _build.twin_record_for_target(TARGET)
_numbers = [int(part) for part in re.findall(r"\d+", VERSION)][:4]
VERSION_TUPLE = tuple(_numbers + [0] * (4 - len(_numbers)))
ICON = str(ROOT / "assets" / "ClaudeRestart.ico")
BUILD_DIR = ROOT / "build"
BUILD_DIR.mkdir(exist_ok=True)


def version_file(original_name: str) -> str:
    """Write a VSVersionInfo file for `original_name` derived from __version__."""
    path = BUILD_DIR / f"version_{original_name}.txt"
    file_version = ".".join(str(part) for part in VERSION_TUPLE)
    path.write_text(
        "VSVersionInfo(\n"
        f"  ffi=FixedFileInfo(filevers={VERSION_TUPLE}, prodvers={VERSION_TUPLE}, mask=0x3F, flags=0x0,\n"
        "                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),\n"
        "  kids=[\n"
        "    StringFileInfo([StringTable('040904B0', [\n"
        "      StringStruct('CompanyName', 'claude-appx-restart project (not affiliated with Anthropic)'),\n"
        "      StringStruct('FileDescription', 'Claude Restart: repairs the stale Claude AppX Job and starts Claude Desktop'),\n"
        f"      StringStruct('FileVersion', '{file_version}'),\n"
        f"      StringStruct('InternalName', '{original_name}'),\n"
        "      StringStruct('LegalCopyright', 'https://github.com/TranDenyDFW/claude-appx-restart'),\n"
        f"      StringStruct('OriginalFilename', '{original_name}.exe'),\n"
        "      StringStruct('ProductName', 'Claude Restart'),\n"
        f"      StringStruct('ProductVersion', '{VERSION}')])]),\n"
        "    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n"
        "  ]\n"
        ")\n",
        encoding="utf-8",
    )
    return str(path)


a = Analysis(
    [str(SOURCE)],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    excludes=["tkinter", "unittest", "pydoc", "doctest", "lib2to3", "test"],
)
pyz = PYZ(a.pure)

_common = dict(debug=False, strip=False, upx=False, icon=ICON, uac_admin=False)

if TARGET == "console":
    EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="ClaudeRestart",
        console=True,
        version=version_file("ClaudeRestart"),
        **_common,
    )
else:
    EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="ClaudeRestart-quiet",
        console=False,
        disable_windowed_traceback=True,
        version=version_file("ClaudeRestart-quiet"),
        **_common,
    )
