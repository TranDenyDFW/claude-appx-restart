# Release process

Two separate controls keep a published release trustworthy, and only one of them is
this repository's code:

- **Atomicity** comes from the workflow. It creates a draft, uploads every asset to it,
  verifies the whole set, and publishes only then. A run that fails at any point leaves
  a draft, never a half-populated public release.
- **Immutability** comes from a repository setting. With immutable releases enabled,
  GitHub itself refuses to move the tag or replace an asset after publication. The
  workflow cannot provide this; it can only check that it is on, which it does after
  publishing, failing the job if it is not.

## Before pushing a tag

Run the preflight from your own shell, because both questions need a token with more
rights than a workflow token has:

```bash
py -3 tools/release_preflight.py --tag v1.0.3
```

It refuses when immutable releases are disabled, and when the tag is already published.
To enable the setting once:

```bash
gh api -X PUT repos/TranDenyDFW/claude-appx-restart/immutable-releases
```

## What the workflow does

1. The build job runs the tests and the self-check, builds both executables in two
   stages so the console build carries a true record of its windowed twin, smoke-tests
   them, and uploads the artifact. It has read-only permissions and never sees a write
   token.
2. The release job takes that artifact, with no checkout, so no repository code runs
   with the write token. It then:
   - reconciles `SHA256SUMS.txt` with `release-manifest.json` and refuses if they
     disagree, or if the manifest is for another tag or another commit;
   - resolves the tag, through an annotated tag object if there is one, and requires it
     to point at the commit the files were built from;
   - refuses when the tag has both a published release and a draft, or more than one
     draft, rather than guessing which to use;
   - creates or reuses a draft, refusing a draft that carries a file this build did not
     produce rather than deleting someone's upload;
   - uploads each asset by release id and re-reads it immediately, so a corrupted or
     incomplete upload stops the run while it is still a draft;
   - verifies name set, state, size and digest, publishes, then verifies again and
     requires the release to be immutable.

## After publishing

```bash
py -3 tools/verify_release.py --tag v1.0.3
```

This downloads every asset and compares it with the digest GitHub reports and with the
published `SHA256SUMS.txt`. Checking both matters: an attacker who could replace an
executable could replace the checksum file alongside it, so the checksum file alone
proves nothing. On Windows it also records the Authenticode status of each executable,
which reads `NotSigned` until the project has a signing identity.

## Re-running a release job

- **Re-run failed jobs** reuses the artifact the build job already produced. This is the
  idempotent path: if the release is already published and identical, the job succeeds
  without touching anything.
- **Re-run all jobs**, or pushing the same tag again after a publish, rebuilds the
  executables. Those bytes are not guaranteed to be identical to the published ones, so
  the comparison is expected to fail. That is the immutability rule working, not a bug.
  The way forward is a new version, never a replaced asset.
- Artifact retention bounds how long the first option remains available.

The ZIP is built deterministically (fixed member order, fixed timestamps), so it is
reproducible from the same inputs. The executables are not claimed to be reproducible.
