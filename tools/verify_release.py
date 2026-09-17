#!/usr/bin/env python3
"""Check a published release by downloading it, not by trusting the page.

Every asset is fetched and hashed. Each digest is compared with what the API reports
and, for the three files it covers, with the published SHA256SUMS.txt, so a tampered
checksum file cannot vouch for tampered executables. On Windows the Authenticode status
of each executable is recorded as well, which reads NotSigned until the project has a
signing identity.

    py -3 tools/verify_release.py --tag v1.0.3
    py -3 tools/verify_release.py --tag v1.0.3 --repo owner/name --keep downloads/

Exit code 0 means every check passed. Anything else means do not distribute the files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


DEFAULT_REPO = "TranDenyDFW/claude-appx-restart"
API = "https://api.github.com"


def fetch(url: str, *, token: str | None = None, accept: str = "application/vnd.github+json") -> bytes:
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "claude-appx-restart-verify"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request) as response:  # noqa: S310 - fixed https host
        return response.read()


def release_for(tag: str, repo: str, token: str | None) -> dict:
    return json.loads(fetch(f"{API}/repos/{repo}/releases/tags/{tag}", token=token).decode("utf-8"))


def expected_names(version: str) -> tuple[str, ...]:
    """The release asset names, from the one definition the build and the application share.

    Keeping a second copy here would let a rename pass this check while the release it is
    checking no longer matches.
    """
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from clauderestart import payload

    return tuple(payload.release_asset_names(version))


def authenticode_status(path: Path) -> str:
    """Report whether Windows considers a file signed. Unsigned is expected for now."""
    if sys.platform != "win32":
        return "not checked (not Windows)"
    command = (
        "$result = Get-AuthenticodeSignature -LiteralPath "
        f"'{path}'; Write-Output $result.Status"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except OSError as exc:
        return f"not checked ({exc})"
    return completed.stdout.strip() or "unknown"


def verify(tag: str, repo: str, into: Path, token: str | None) -> list[str]:
    """Return every problem found. An empty list means the release is what it claims."""
    problems: list[str] = []
    release = release_for(tag, repo, token)
    version = tag[1:] if tag.startswith("v") else tag
    if release.get("draft"):
        problems.append("the release is still a draft")
    if not release.get("immutable"):
        problems.append("the release is not immutable, so its files can still be replaced")
    assets = {asset["name"]: asset for asset in release.get("assets", [])}
    names = expected_names(version)
    if sorted(assets) != sorted(names):
        problems.append(f"the release carries {sorted(assets)}, expected {sorted(names)}")
        return problems

    digests: dict[str, str] = {}
    for name in names:
        asset = assets[name]
        if asset.get("state") != "uploaded":
            problems.append(f"{name} is {asset.get('state')}, not uploaded")
            continue
        reported = str(asset.get("digest") or "").replace("sha256:", "")
        if not reported:
            problems.append(f"{name} has no digest")
            continue
        data = fetch(asset["browser_download_url"], token=token, accept="application/octet-stream")
        observed = hashlib.sha256(data).hexdigest()
        digests[name] = observed
        if observed != reported:
            problems.append(f"{name} downloaded as {observed}, but the release reports {reported}")
        if int(asset.get("size") or 0) != len(data):
            problems.append(f"{name} is {len(data)} bytes, but the release reports {asset.get('size')}")
        (into / name).write_bytes(data)

    checksums = into / "SHA256SUMS.txt"
    if checksums.is_file():
        listed = {}
        for line in checksums.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, _, name = line.partition("  ")
            listed[name.strip()] = digest.strip()
        for name, digest in listed.items():
            if name not in digests:
                problems.append(f"SHA256SUMS.txt names {name}, which the release does not carry")
            elif digests[name] != digest:
                problems.append(f"SHA256SUMS.txt says {name} is {digest}, but it downloaded as {digests[name]}")
        missing = [name for name in names if name not in listed and name != "SHA256SUMS.txt"]
        if missing:
            problems.append(f"SHA256SUMS.txt does not cover {missing}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Download a release and check it against its own digests.")
    parser.add_argument("--tag", required=True, help="the release tag, for example v1.0.3")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/name (default: {DEFAULT_REPO})")
    parser.add_argument("--keep", metavar="DIR", help="keep the downloaded files in DIR")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or None
    holder = tempfile.TemporaryDirectory() if not args.keep else None
    into = Path(args.keep) if args.keep else Path(holder.name)
    into.mkdir(parents=True, exist_ok=True)
    try:
        try:
            problems = verify(args.tag, args.repo, into, token)
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            print(f"Could not check {args.tag}: {exc}", file=sys.stderr)
            return 2
        for name in expected_names(args.tag[1:] if args.tag.startswith("v") else args.tag):
            path = into / name
            if path.suffix == ".exe" and path.is_file():
                print(f"{name}: Authenticode {authenticode_status(path)}")
        if problems:
            print(f"\n{args.tag} did NOT verify:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print(f"\n{args.tag} verified: every asset matches its published digest.")
        return 0
    finally:
        if holder is not None:
            holder.cleanup()


if __name__ == "__main__":
    sys.exit(main())
