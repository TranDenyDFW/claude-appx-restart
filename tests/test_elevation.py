"""The elevated relaunch request."""

from __future__ import annotations

import ctypes
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

from clauderestart import elevation, payload, winapi  # noqa: E402


class ElevationLayoutTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8, "x64 Windows layout")
    def test_shellexecuteinfo_layout_matches_win64(self) -> None:
        self.assertEqual(ctypes.sizeof(winapi.SHELLEXECUTEINFOW), 112)


class ElevationRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.exe = self.root / payload.CONSOLE_EXE_NAME
        self.exe.write_bytes(b"")

    def test_elevation_request_frozen_has_no_script_argument(self) -> None:
        with support.frozen_at(self.exe):
            target, parameters, workdir = elevation.elevation_request(["--yes", "--pause", "--elevated"])
        self.assertEqual(Path(target), self.exe)
        self.assertEqual(parameters, "--yes --pause --elevated")
        self.assertEqual(Path(workdir), self.root)

    def test_elevation_request_from_source_keeps_the_entry_script_first(self) -> None:
        target, parameters, workdir = elevation.elevation_request(["--yes"])
        script = str(payload.SOURCE_ENTRY)
        self.assertEqual(Path(target), Path(sys.executable).resolve())
        self.assertTrue(parameters.startswith(script) or parameters.startswith(f'"{script}"'), parameters)
        self.assertTrue(parameters.endswith("--yes --elevated"), parameters)
        self.assertEqual(Path(workdir), support.ROOT)


if __name__ == "__main__":
    unittest.main()
