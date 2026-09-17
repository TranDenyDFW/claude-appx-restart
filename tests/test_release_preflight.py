"""The pre-tag check: a lookup that fails never reads as ready to publish."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402


def load_preflight():
    path = support.ROOT / "tools" / "release_preflight.py"
    spec = importlib.util.spec_from_file_location("release_preflight", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreflightTests(unittest.TestCase):
    def run_with(self, release_lookup: tuple[int, str, str]) -> tuple[int, str]:
        preflight = load_preflight()

        def gh(*arguments: str) -> tuple[int, str, str]:
            if arguments[-1].endswith("/immutable-releases"):
                return 0, '{"enabled": true}', ""
            return release_lookup

        stderr = io.StringIO()
        with mock.patch.object(preflight, "gh", side_effect=gh), mock.patch.object(
            sys, "argv", ["release_preflight.py", "--tag", "v1.0.3"]
        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = preflight.main()
        return code, stderr.getvalue()

    def test_an_unpublished_tag_is_ready(self) -> None:
        # What the real gh prints for a missing release.
        code, _ = self.run_with((1, "", "gh: Not Found (HTTP 404)"))
        self.assertEqual(code, 0)

    def test_a_published_tag_is_refused(self) -> None:
        code, errors = self.run_with((0, '{"id": 1}', ""))
        self.assertEqual(code, 1)
        self.assertIn("already published", errors)

    def test_a_lookup_that_fails_is_not_read_as_unpublished(self) -> None:
        code, errors = self.run_with((1, "", "gh: Server Error (HTTP 502)"))
        self.assertEqual(code, 1)
        self.assertIn("could not tell whether v1.0.3 is already published", errors)
        self.assertIn("HTTP 502", errors)


if __name__ == "__main__":
    unittest.main()
