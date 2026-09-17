#!/usr/bin/env python3
"""Check that a release can be published safely, before the tag is pushed.

Two questions, both needing a token with more rights than a workflow gets, which is why
this runs from a maintainer's own shell rather than from CI:

1. Are immutable releases enabled for the repository? Without that, a published asset
   can still be replaced, and the workflow's comparison would be comparing against
   something changeable.
2. Is the tag still unpublished? Publishing over an existing release is refused by the
   workflow, so this says so before the tag is pushed rather than after.

    py -3 tools/release_preflight.py --tag v1.0.3
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


DEFAULT_REPO = "TranDenyDFW/claude-appx-restart"


def gh(*arguments: str) -> tuple[int, str, str]:
    completed = subprocess.run(
        ["gh", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the repository is ready to publish a release.")
    parser.add_argument("--tag", required=True, help="the tag about to be pushed, for example v1.0.3")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/name (default: {DEFAULT_REPO})")
    args = parser.parse_args()

    problems: list[str] = []

    code, out, err = gh("api", f"repos/{args.repo}/immutable-releases")
    if code != 0:
        problems.append(
            "could not read the immutable releases setting "
            f"({err or 'no output'}); this needs a token with administration access"
        )
    else:
        try:
            enabled = bool(json.loads(out).get("enabled"))
        except ValueError:
            enabled = False
            problems.append(f"the immutable releases setting could not be read: {out}")
        if not enabled:
            problems.append(
                "immutable releases are disabled. Enable them in Settings, General, Releases, or run: "
                f"gh api -X PUT repos/{args.repo}/immutable-releases"
            )
        else:
            print("Immutable releases: enabled")

    code, out, err = gh("api", f"repos/{args.repo}/releases/tags/{args.tag}")
    if code == 0:
        problems.append(f"{args.tag} is already published; publish a new version instead of reusing this tag")
    elif "(HTTP 404)" in err:
        print(f"Tag {args.tag}: not published yet")
    else:
        # Only a 404 says there is no published release; a failed lookup says nothing.
        problems.append(f"could not tell whether {args.tag} is already published ({err or 'no output'})")

    if problems:
        print("\nNot ready to publish:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"\nReady: pushing {args.tag} will publish a draft-first, immutable release.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
