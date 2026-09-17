"""The release script, run for real against stand-ins for GitHub.

The script inside the workflow is extracted and executed under Git Bash, with `gh` and
`curl` replaced by recorders that answer from a fixture. Each case asserts both the exit
status and, just as importantly, which mutating calls were made: a refusal that still
deleted an asset would be no refusal at all.

Skipped when Git Bash is unavailable. The bash on PATH here is a WSL launcher, so the
one shipped with Git for Windows is located explicitly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402


VERSION = "1.0.3"
TAG = f"v{VERSION}"
BUILT_SHA = "1111111111111111111111111111111111111111"
ZIP_NAME = f"ClaudeRestart-v{VERSION}-win-x64.zip"
ASSET_BYTES = {
    ZIP_NAME: b"the release archive",
    "ClaudeRestart.exe": b"the console executable",
    "ClaudeRestart-quiet.exe": b"the windowed executable",
}
MUTATING = ("release create", "-X DELETE", "-X PATCH", "curl")
# The checks the script makes before it calls anything. A run that refuses on one of
# these records no call, so these are what prove it ran at all.
SCRIPT_REFUSALS = (
    "the build is for",
    "the build is from commit",
    "SHA256SUMS.txt names",
    "the manifest disagree about",
    "the manifest must add exactly",
    "does not describe the SHA256SUMS.txt",
)


def git_bash() -> Path | None:
    """The bash that ships with Git for Windows, never the WSL launcher on PATH."""
    candidates = []
    git = shutil.which("git")
    if git:
        try:
            exec_path = subprocess.run(
                [git, "--exec-path"], capture_output=True, text=True, check=False
            ).stdout.strip()
        except OSError:
            exec_path = ""
        if exec_path:
            candidates.append(Path(exec_path).parents[2] / "bin" / "bash.exe")
    candidates.append(Path(r"C:\Program Files\Git\bin\bash.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def release_script() -> str:
    """The script as the workflow runner sees it: dedented the way YAML dedents it.

    The slice starts at the beginning of the marker's line, not at the marker, so the
    marker's own indentation counts. Stripping the smallest indentation in the block is
    what makes a here-document terminator land in column one, where bash needs it.
    """
    text = (support.ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    marker = text.index("# BEGIN release-script")
    start = text.rfind("\n", 0, marker) + 1
    end = text.index("# END release-script") + len("# END release-script")
    block = text[start:end].splitlines()
    indent = min(len(line) - len(line.lstrip()) for line in block if line.strip())
    return "\n".join(line[indent:] if len(line) >= indent else line for line in block) + "\n"


SHIM = r'''#!/usr/bin/env python3
"""Stand in for gh and curl: answer from state.json, and record every call."""
import json, os, pathlib, sys

STATE = pathlib.Path(os.environ["SHIM_STATE"])
CALLS = pathlib.Path(os.environ["SHIM_CALLS"])
state = json.loads(STATE.read_text(encoding="utf-8"))
# The wrapper passes the tool it stands for as the first argument, because argv[0] is
# this file's own path once the wrapper execs it.
tool = sys.argv[1]
argv = sys.argv[2:]
CALLS.write_text(CALLS.read_text(encoding="utf-8") + f"{tool} {' '.join(argv)}\n", encoding="utf-8")


def save():
    STATE.write_text(json.dumps(state), encoding="utf-8")


def select(payload):
    """Apply the --jq selector the caller asked for, as gh itself would."""
    if "--jq" not in argv:
        return payload
    expression = argv[argv.index("--jq") + 1]
    if isinstance(payload, str):
        return payload
    if expression.startswith(".") and "[]" not in expression:
        value = payload
        for part in expression.lstrip(".").split("."):
            if part:
                value = value.get(part) if isinstance(value, dict) else None
        return value if isinstance(value, str) else json.dumps(value)
    if expression.startswith(".[]"):
        rows = payload if isinstance(payload, list) else [payload]
        fields = [part for part in expression.replace(".[]", "").split("|")[-1].strip().lstrip(".").split(".") if part]
        lines = []
        for row in rows:
            value = row
            for part in fields:
                value = value.get(part) if isinstance(value, dict) else None
            lines.append("" if value is None else str(value))
        return "\n".join(lines)
    return json.dumps(payload)


def out(payload):
    payload = select(payload)
    sys.stdout.write(payload if isinstance(payload, str) else json.dumps(payload))
    sys.exit(0)


def fail(message, code=1):
    sys.stderr.write(message + "\n")
    sys.exit(code)


if state.get("fail_next") and state["fail_next"] in " ".join(argv):
    state.pop("fail_next")
    save()
    fail("the shim was told to fail here")

if tool == "curl":
    target = [a for a in argv if a.startswith("http")][0]
    # Parse the query the way the real endpoint does: the upload URL carries name and
    # label, so slicing at name= and taking the rest swallows every later parameter.
    query = target.split("?", 1)[1] if "?" in target else ""
    fields = dict(part.split("=", 1) for part in query.split("&") if "=" in part)
    name = fields["name"]
    upload = state.setdefault("uploaded", [])
    upload.append(name)
    release = state["releases"][str(state["draft_id"])]
    digest = state["digests"].get(name)
    if state.get("corrupt_upload") == name:
        digest = "0" * 64
    release["assets"].append(
        {
            "id": 1000 + len(release["assets"]),
            "name": name,
            "state": state.get("upload_state", "uploaded"),
            "size": state["sizes"][name],
            "digest": None if state.get("no_digest") == name else f"sha256:{digest}",
        }
    )
    state["reads_since_upload"] = 0
    save()
    out("{}")

if tool != "gh":
    fail(f"unexpected tool {tool}")

if argv[:1] == ["release"] and argv[1:2] == ["create"]:
    new_id = str(max([int(k) for k in state["releases"]] + [100]) + 1)
    state["releases"][new_id] = {"id": int(new_id), "tag_name": os.environ["TAG"], "draft": True,
                                 "immutable": False, "assets": [],
                                 "upload_url": f"https://uploads.invalid/{new_id}/assets{{?name,label}}"}
    state["draft_id"] = int(new_id)
    save()
    out("created")

if argv[:1] == ["api"]:
    # Values belonging to a flag are not the endpoint: -X PATCH must not be read as a path.
    value_flags = {"-X", "--method", "-F", "-f", "-H", "--jq", "--input"}
    rest = []
    skip = False
    for item in argv[1:]:
        if skip:
            skip = False
            continue
        if item in value_flags:
            skip = True
            continue
        if item.startswith("-"):
            continue
        rest.append(item)
    method = "GET"
    if "-X" in argv:
        method = argv[argv.index("-X") + 1]
    elif "--method" in argv:
        method = argv[argv.index("--method") + 1]
    path = rest[0]
    releases = state["releases"]
    if method == "DELETE" and "/releases/assets/" in path:
        asset_id = int(path.rsplit("/", 1)[-1])
        for release in releases.values():
            release["assets"] = [a for a in release["assets"] if a["id"] != asset_id]
        save()
        out("{}")
    if method == "PATCH":
        release_id = path.rsplit("/", 1)[-1]
        if state.get("patch_fails_once") and not state.get("patch_failed"):
            state["patch_failed"] = True
            save()
            fail("the publish call failed", 1)
        releases[release_id]["draft"] = False
        releases[release_id]["immutable"] = state.get("immutable_after_publish", True)
        save()
        out("{}")
    if path.endswith(f"/releases/tags/{os.environ['TAG']}"):
        if state.get("release_lookup_error"):
            fail(state["release_lookup_error"], 1)
        for release in releases.values():
            if release["tag_name"] == os.environ["TAG"] and not release["draft"]:
                out(release)
        # What the real gh prints for a missing release, captured from gh itself.
        fail("gh: Not Found (HTTP 404)", 1)
    if path.endswith("/releases"):
        out(list(releases.values()))
    if "/git/ref/tags/" in path:
        state["tag_reads"] = int(state.get("tag_reads", 0)) + 1
        save()
        moved = state.get("tag_sha_after_read")
        if moved and state["tag_reads"] >= int(state.get("tag_moves_at_read", 2)):
            out({"object": {"sha": moved, "type": "commit"}})
        if state.get("annotated_tag"):
            # An annotated tag points at a tag object, which has to be dereferenced again.
            out({"object": {"sha": "a" * 40, "type": "tag"}})
        out({"object": {"sha": state.get("tag_sha", os.environ["BUILT_SHA"]), "type": "commit"}})
    if "/git/tags/" in path:
        out({"object": {"sha": state.get("tag_sha", os.environ["BUILT_SHA"]), "type": "commit"}})
    if path.endswith("/assets"):
        release_id = path.split("/releases/")[1].split("/")[0]
        state["reads_since_upload"] = int(state.get("reads_since_upload", 0)) + 1
        save()
        listed = [dict(asset) for asset in releases[release_id]["assets"]]
        spoil = state.get("corrupt_asset")
        if spoil and state["reads_since_upload"] >= 2:
            for asset in listed:
                if asset["name"] == spoil:
                    asset["digest"] = "sha256:" + "0" * 64
        out(listed)
    if "/releases/" in path:
        release_id = path.rsplit("/", 1)[-1]
        out(releases[release_id])
fail(f"unhandled call: {argv}")
'''


@unittest.skipUnless(git_bash() is not None, "Git Bash is required to run the release script")
class ReleaseScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.dist = self.work / "dist"
        self.dist.mkdir()
        digests = {}
        sizes = {}
        for name, data in ASSET_BYTES.items():
            (self.dist / name).write_bytes(data)
            digests[name] = __import__("hashlib").sha256(data).hexdigest()
            sizes[name] = len(data)
        lines = [f"{digests[name]}  {name}" for name in ("ClaudeRestart.exe", "ClaudeRestart-quiet.exe", ZIP_NAME)]
        checksums = ("\n".join(lines) + "\n").encode("utf-8")
        (self.dist / "SHA256SUMS.txt").write_bytes(checksums)
        digests["SHA256SUMS.txt"] = __import__("hashlib").sha256(checksums).hexdigest()
        sizes["SHA256SUMS.txt"] = len(checksums)
        manifest = {
            "version": VERSION,
            "tag": TAG,
            "commit": BUILT_SHA,
            "assets": [{"name": name, "sha256": digests[name], "size": sizes[name]} for name in digests],
        }
        (self.dist / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.digests = digests
        self.sizes = sizes

        self.bin = self.work / "bin"
        self.bin.mkdir()
        shim = self.bin / "shim.py"
        shim.write_text(SHIM, encoding="utf-8")
        for tool in ("gh", "curl"):
            wrapper = f'#!/bin/sh\nexec "{sys.executable}" "{shim}" {tool} "$@"\n'.replace("\\", "/")
            (self.bin / tool).write_text(wrapper, encoding="utf-8", newline="\n")
            os.chmod(self.bin / tool, 0o755)
        self.state_path = self.work / "state.json"
        self.calls_path = self.work / "calls.txt"
        self.calls_path.write_text("", encoding="utf-8")
        self.script = self.work / "release.sh"
        self.script.write_text(release_script(), encoding="utf-8", newline="\n")

    def rewrite_manifest(self, **overrides: object) -> None:
        """Change one field of the build manifest the release job reads."""
        path = self.dist / "release-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest.update(overrides)
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def state(self, **overrides: object) -> None:
        state = {
            "releases": {},
            "digests": self.digests,
            "sizes": self.sizes,
            "draft_id": None,
        }
        state.update(overrides)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def published_release(self, *, immutable: bool = True, digests: dict[str, str] | None = None) -> dict:
        digests = digests or self.digests
        return {
            "id": 500,
            "tag_name": TAG,
            "draft": False,
            "immutable": immutable,
            "upload_url": "https://uploads.invalid/500/assets{?name,label}",
            "assets": [
                {"id": 600 + index, "name": name, "state": "uploaded", "size": self.sizes[name],
                 "digest": f"sha256:{digests[name]}"}
                for index, name in enumerate(self.digests)
            ],
        }

    def to_posix(self, path: Path) -> str:
        """Convert a Windows path the way the shell itself would."""
        result = subprocess.run(
            [str(git_bash()), "-c", f'cygpath -u "{path}"'], capture_output=True, text=True, check=False
        )
        return result.stdout.strip()

    def run_script(self) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.update(
            {
                "GH_TOKEN": "token",
                "GH_REPO": "owner/name",
                "TAG": TAG,
                "BUILT_SHA": BUILT_SHA,
                "SHIM_STATE": str(self.state_path),
                "SHIM_CALLS": str(self.calls_path),
            }
        )
        # The shell puts its own bin directories ahead of any inherited PATH, and it
        # ships a curl of its own, so the stand-ins are prepended from inside the shell
        # instead. Without this the script would reach the real GitHub and the real
        # network, and these tests would prove nothing.
        bin_dir = self.to_posix(self.bin)
        script = self.to_posix(self.script)
        # Require the gh on PATH to be the stand-in itself. Checking only that some gh
        # exists passes on any machine with the real one installed, and the script would
        # then reach the real GitHub, which is the thing this prepending exists to prevent.
        command = (
            f'export PATH="{bin_dir}:$PATH"; '
            f'[ "$(command -v gh)" = "{bin_dir}/gh" ] || exit 97; '
            f'[ "$(command -v curl)" = "{bin_dir}/curl" ] || exit 97; '
            f'exec bash "{script}"'
        )
        return subprocess.run(
            [str(git_bash()), "-c", command],
            cwd=self.work,
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def assert_ran(self, result: subprocess.CompletedProcess) -> None:
        """The script itself ran, rather than never starting.

        A scenario that asserts only a non-zero exit and no mutating call cannot tell a
        refusal from a script that never began, so every run is held to this: either it
        reached the stand-ins, or it refused with one of its own checks that run first.
        """
        self.assertNotEqual(result.returncode, 97, "the stand-ins were not on PATH")
        if self.calls():
            return
        output = result.stdout + result.stderr
        self.assertTrue(
            any(phrase in output for phrase in SCRIPT_REFUSALS),
            f"the script made no call and gave none of its own refusals:\n{output}",
        )

    def assert_used_stand_ins(self, result: subprocess.CompletedProcess) -> None:
        self.assertNotEqual(result.returncode, 97, "the stand-ins were not on PATH")
        self.assertTrue(self.calls(), "the script made no recorded calls, so it reached something else")

    def calls(self) -> list[str]:
        return [line for line in self.calls_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def mutations(self) -> list[str]:
        return [call for call in self.calls() if any(marker in call for marker in MUTATING)]

    def current(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def test_a_clean_run_publishes_only_after_every_asset_verifies(self) -> None:
        self.state()
        result = self.run_script()
        self.assert_ran(result)
        self.assert_used_stand_ins(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        releases = list(self.current()["releases"].values())
        self.assertEqual(len(releases), 1)
        self.assertFalse(releases[0]["draft"], "the release ends up published")
        self.assertEqual(sorted(a["name"] for a in releases[0]["assets"]), sorted(self.digests))
        calls = self.calls()
        publish = [index for index, call in enumerate(calls) if "-X PATCH" in call][0]
        last_upload = [index for index, call in enumerate(calls) if call.startswith("curl")][-1]
        self.assertGreater(publish, last_upload, "publishing happens after the uploads")

    def test_a_failure_during_upload_leaves_the_release_a_draft(self) -> None:
        self.state(fail_next="ClaudeRestart.exe")
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        releases = list(self.current()["releases"].values())
        self.assertTrue(releases and releases[0]["draft"], "an interrupted publish stays a draft")

    def test_an_upload_that_arrives_corrupted_stops_before_publishing(self) -> None:
        self.state(corrupt_upload="ClaudeRestart-quiet.exe")
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all("-X PATCH" not in call for call in self.calls()), self.calls())

    def test_a_tag_that_moves_before_publishing_stops_without_publishing(self) -> None:
        # The tag points at the built commit when the draft is made and moves afterwards.
        # Only the check taken immediately before the publish can see that.
        self.state(tag_sha_after_read="0" * 40, tag_moves_at_read=2)
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all("-X PATCH" not in call for call in self.calls()), self.calls())

    def test_an_asset_that_changes_after_its_upload_check_stops_without_publishing(self) -> None:
        # Each upload is re-read as it happens, and this asset passes that. It only goes wrong
        # on the listing taken immediately before publishing, so the pre-publish verification
        # is the only thing that can refuse it.
        self.state(corrupt_asset="ClaudeRestart-quiet.exe")
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all("-X PATCH" not in call for call in self.calls()), self.calls())

    def test_an_asset_still_uploading_stops_before_publishing(self) -> None:
        self.state(upload_state="open")
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all("-X PATCH" not in call for call in self.calls()))

    def test_a_publish_that_fails_once_succeeds_on_the_next_run(self) -> None:
        # Re-running the failed job must be safe: the draft is still there, and the second
        # attempt publishes it rather than making a second release.
        self.state(patch_fails_once=True)
        first = self.run_script()
        self.assert_ran(first)
        self.assertNotEqual(first.returncode, 0)
        releases = list(self.current()["releases"].values())
        self.assertTrue(releases and releases[0]["draft"], "a failed publish leaves the draft alone")
        second = self.run_script()
        self.assert_ran(second)
        self.assertEqual(second.returncode, 0, second.stderr)
        releases = list(self.current()["releases"].values())
        self.assertEqual(len(releases), 1, releases)
        self.assertFalse(releases[0]["draft"])

    def test_a_published_release_beside_a_draft_is_refused(self) -> None:
        # Ambiguous state is refused rather than guessed at, and nothing is changed.
        draft = {
            "id": 501,
            "tag_name": TAG,
            "draft": True,
            "immutable": False,
            "upload_url": "https://uploads.invalid/501/assets{?name,label}",
            "assets": [],
        }
        self.state(releases={"500": self.published_release(), "501": draft})
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        mutating = [call for call in self.calls() if any(token in call for token in MUTATING)]
        self.assertEqual(mutating, [], self.calls())

    def test_a_manifest_that_disagrees_with_the_checksums_is_refused(self) -> None:
        # Change the manifest, not the checksum file. Tampering the file is caught first by
        # the manifest's own entry for that file, so the agreement rule between the two would
        # never be the thing that refused, and this scenario would pass for the wrong reason.
        path = self.dist / "release-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for entry in manifest["assets"]:
            if entry["name"] == "ClaudeRestart-quiet.exe":
                entry["sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.state()
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        mutating = [call for call in self.calls() if any(token in call for token in MUTATING)]
        self.assertEqual(mutating, [], self.calls())

    def test_a_manifest_from_another_commit_is_refused(self) -> None:
        self.rewrite_manifest(commit="9" * 40)
        self.state()
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        mutating = [call for call in self.calls() if any(token in call for token in MUTATING)]
        self.assertEqual(mutating, [], self.calls())

    def test_a_manifest_with_no_commit_is_refused(self) -> None:
        # A manifest built outside Actions carries no commit, and must not be publishable.
        self.rewrite_manifest(commit=None)
        self.state()
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        mutating = [call for call in self.calls() if any(token in call for token in MUTATING)]
        self.assertEqual(mutating, [], self.calls())

    def test_a_manifest_for_another_tag_is_refused(self) -> None:
        self.rewrite_manifest(tag="v9.9.9")
        self.state()
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        mutating = [call for call in self.calls() if any(token in call for token in MUTATING)]
        self.assertEqual(mutating, [], self.calls())

    def test_a_checksum_file_the_manifest_does_not_describe_is_refused(self) -> None:
        # Nothing else can vouch for SHA256SUMS.txt: it cannot list its own digest, so the
        # manifest's entry for it is the only check that the file shipped is the file built.
        sums = self.dist / "SHA256SUMS.txt"
        sums.write_text(sums.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.state()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not describe the SHA256SUMS.txt", result.stdout + result.stderr)
        self.assertEqual(self.mutations(), [], self.calls())

    def test_a_manifest_describing_an_asset_the_checksums_never_listed_is_refused(self) -> None:
        # The manifest may add exactly one entry the checksum file cannot carry, its own.
        # Anything else means it describes a release the checksums never covered.
        manifest = json.loads((self.dist / "release-manifest.json").read_text(encoding="utf-8"))
        manifest["assets"].append({"name": "extra.bin", "sha256": "0" * 64, "size": 1})
        (self.dist / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.state()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must add exactly SHA256SUMS.txt", result.stdout + result.stderr)
        self.assertEqual(self.mutations(), [], self.calls())

    def test_an_asset_that_reports_no_digest_stops_before_publishing(self) -> None:
        # An asset GitHub has not finished hashing has a null digest. There is nothing to
        # compare against, so it must be refused rather than treated as a match.
        self.state(no_digest="ClaudeRestart-quiet.exe")
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all("-X PATCH" not in call for call in self.calls()), self.calls())

    def test_an_annotated_tag_that_peels_to_the_built_commit_publishes(self) -> None:
        self.state(annotated_tag=True)
        result = self.run_script()
        self.assert_ran(result)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_identical_published_release_is_left_alone(self) -> None:
        self.state(releases={"500": self.published_release()})
        result = self.run_script()
        self.assert_ran(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [], "an identical release is never touched")

    def test_a_published_release_that_differs_fails_without_touching_it(self) -> None:
        changed = dict(self.digests)
        changed["ClaudeRestart.exe"] = "9" * 64
        self.state(releases={"500": self.published_release(digests=changed)})
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_a_release_lookup_that_fails_is_not_read_as_unpublished(self) -> None:
        # Read as unpublished, the script would create a draft beside the release that exists.
        self.state(
            releases={"500": self.published_release()},
            release_lookup_error="gh: Server Error (HTTP 502)",
        )
        result = self.run_script()
        self.assert_used_stand_ins(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not tell whether", result.stderr)
        self.assertIn("HTTP 502", result.stderr)
        self.assertEqual(self.mutations(), [])

    def test_a_published_release_that_is_not_immutable_fails(self) -> None:
        self.state(releases={"500": self.published_release(immutable=False)})
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable", result.stderr)
        self.assertEqual(self.mutations(), [])

    def test_a_draft_holding_an_unexpected_file_is_refused(self) -> None:
        draft = self.published_release()
        draft["draft"] = True
        draft["assets"].append({"id": 999, "name": "notes.txt", "state": "uploaded", "size": 1,
                                "digest": "sha256:" + "0" * 64})
        self.state(releases={"500": draft}, draft_id=500)
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("notes.txt", result.stderr)
        self.assertEqual(self.mutations(), [], "a stray file is never deleted for the user")

    def test_two_drafts_for_one_tag_are_refused(self) -> None:
        first = self.published_release()
        first["draft"] = True
        second = dict(first, id=501)
        self.state(releases={"500": first, "501": second})
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_a_tag_that_moved_after_the_build_is_refused(self) -> None:
        self.state(tag_sha="2" * 40)
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("built from", result.stderr)
        self.assertEqual(self.mutations(), [], "nothing is created for a tag that moved")

    def test_a_publish_that_does_not_become_immutable_is_reported(self) -> None:
        self.state(immutable_after_publish=False)
        result = self.run_script()
        self.assert_ran(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable", result.stderr)


if __name__ == "__main__":
    unittest.main()
