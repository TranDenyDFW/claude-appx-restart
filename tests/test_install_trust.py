"""Where the install folder comes from: the Windows shell, never the environment."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from clauderestart import install, payload, winapi  # noqa: E402


class ProgramFilesTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "known folders are Windows-only")
    def test_program_files_comes_from_the_shell_not_the_environment(self) -> None:
        winapi.configure()
        real = winapi.program_files_dir()
        self.assertTrue(real.is_absolute() and real.is_dir())
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"ProgramFiles": tmp, "ProgramW6432": tmp}):
                self.assertEqual(winapi.program_files_dir(), real)
        self.assertEqual(install.install_dir(), real / payload.INSTALL_DIRNAME)


if __name__ == "__main__":
    unittest.main()
