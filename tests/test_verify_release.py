"""The release verifier: it must fail on anything that is not exactly what was built.

Every case answers one question: if a published release were wrong in this particular
way, would the tool say so? The network is replaced by a fixture, so the checks are
exercised without downloading anything.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402

_spec = importlib.util.spec_from_file_location("verify_release", support.ROOT / "tools" / "verify_release.py")
verify_release = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = verify_release
_spec.loader.exec_module(verify_release)


VERSION = "1.0.3"
TAG = f"v{VERSION}"
ZIP_NAME = f"ClaudeRestart-v{VERSION}-win-x64.zip"
CONTENT = {
    ZIP_NAME: b"the release archive",
    "ClaudeRestart.exe": b"the console executable",
    "ClaudeRestart-quiet.exe": b"the windowed executable",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checksums_text(content: dict[str, bytes]) -> bytes:
    order = ("ClaudeRestart.exe", "ClaudeRestart-quiet.exe", ZIP_NAME)
    return ("\n".join(f"{digest(content[name])}  {name}" for name in order) + "\n").encode("utf-8")


class Fixture:
    """A published release, and the bytes each asset would download as."""

    def __init__(self, **overrides: object) -> None:
        self.content = dict(CONTENT)
        self.content["SHA256SUMS.txt"] = checksums_text(self.content)
        self.release: dict[str, object] = {
            "draft": False,
            "immutable": True,
            "assets": [
                {
                    "name": name,
                    "state": "uploaded",
                    "size": len(data),
                    "digest": f"sha256:{digest(data)}",
                    "browser_download_url": f"https://example.invalid/{name}",
                }
                for name, data in self.content.items()
            ],
        }
        self.release.update(overrides)

    def asset(self, name: str) -> dict:
        for asset in self.release["assets"]:  # type: ignore[index]
            if asset["name"] == name:
                return asset
        raise KeyError(name)

    def fetch(self, url: str, *, token: object = None, accept: str = "") -> bytes:
        if url.endswith(f"/releases/tags/{TAG}"):
            return json.dumps(self.release).encode("utf-8")
        name = url.rsplit("/", 1)[-1]
        return self.content[name]

    def problems(self) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(verify_release, "fetch", self.fetch):
            return verify_release.verify(TAG, "owner/name", Path(tmp), None)


class VerifyReleaseTests(unittest.TestCase):
    def test_a_release_that_matches_reports_no_problems(self) -> None:
        self.assertEqual(Fixture().problems(), [])

    def test_a_tampered_executable_is_caught_by_its_digest(self) -> None:
        fixture = Fixture()
        fixture.content["ClaudeRestart-quiet.exe"] = b"a different windowed executable"
        problems = fixture.problems()
        self.assertTrue(any("downloaded as" in problem for problem in problems), problems)

    def test_a_tampered_checksums_file_cannot_vouch_for_the_executables(self) -> None:
        # The checksum file is replaced along with the executable, and its own digest is
        # updated to match, exactly as an attacker with write access would do.
        fixture = Fixture()
        fixture.content["ClaudeRestart.exe"] = b"a different console executable"
        fixture.content["SHA256SUMS.txt"] = checksums_text(fixture.content)
        fixture.asset("SHA256SUMS.txt")["digest"] = f"sha256:{digest(fixture.content['SHA256SUMS.txt'])}"
        fixture.asset("SHA256SUMS.txt")["size"] = len(fixture.content["SHA256SUMS.txt"])
        problems = fixture.problems()
        self.assertTrue(
            any("ClaudeRestart.exe" in problem and "downloaded as" in problem for problem in problems), problems
        )

    def test_a_missing_asset_is_reported(self) -> None:
        fixture = Fixture()
        fixture.release["assets"] = [a for a in fixture.release["assets"] if a["name"] != "SHA256SUMS.txt"]
        self.assertTrue(any("expected" in problem for problem in fixture.problems()))

    def test_an_extra_asset_is_reported(self) -> None:
        fixture = Fixture()
        fixture.release["assets"].append(
            {"name": "notes.txt", "state": "uploaded", "size": 1, "digest": "sha256:" + "0" * 64,
             "browser_download_url": "https://example.invalid/notes.txt"}
        )
        self.assertTrue(any("expected" in problem for problem in fixture.problems()))

    def test_a_draft_release_is_reported(self) -> None:
        self.assertTrue(any("draft" in problem for problem in Fixture(draft=True).problems()))

    def test_a_release_that_is_not_immutable_is_reported(self) -> None:
        problems = Fixture(immutable=False).problems()
        self.assertTrue(any("immutable" in problem for problem in problems), problems)

    def test_an_asset_still_uploading_is_reported(self) -> None:
        fixture = Fixture()
        fixture.asset("ClaudeRestart.exe")["state"] = "open"
        self.assertTrue(any("not uploaded" in problem for problem in fixture.problems()))

    def test_an_asset_without_a_digest_is_reported(self) -> None:
        fixture = Fixture()
        fixture.asset("ClaudeRestart.exe")["digest"] = None
        self.assertTrue(any("no digest" in problem for problem in fixture.problems()))

    def test_a_wrong_size_is_reported(self) -> None:
        fixture = Fixture()
        fixture.asset(ZIP_NAME)["size"] = 999999
        self.assertTrue(any("bytes" in problem for problem in fixture.problems()))

    def test_a_checksums_file_that_omits_a_file_is_reported(self) -> None:
        fixture = Fixture()
        text = fixture.content["SHA256SUMS.txt"].decode("utf-8").splitlines()
        fixture.content["SHA256SUMS.txt"] = ("\n".join(text[:-1]) + "\n").encode("utf-8")
        fixture.asset("SHA256SUMS.txt")["digest"] = f"sha256:{digest(fixture.content['SHA256SUMS.txt'])}"
        fixture.asset("SHA256SUMS.txt")["size"] = len(fixture.content["SHA256SUMS.txt"])
        problems = fixture.problems()
        self.assertTrue(any("does not cover" in problem for problem in problems), problems)

    def test_the_expected_names_follow_the_version(self) -> None:
        self.assertEqual(
            sorted(verify_release.expected_names("9.9.9")),
            sorted(["ClaudeRestart-v9.9.9-win-x64.zip", "ClaudeRestart.exe", "ClaudeRestart-quiet.exe", "SHA256SUMS.txt"]),
        )


if __name__ == "__main__":
    unittest.main()
