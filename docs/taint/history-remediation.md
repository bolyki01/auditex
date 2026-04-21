# Git History Remediation Record

Date: 2026-04-18

Purpose: remove old source-history exposure from the packaged repository used for a proprietary Auditex release.

## Action in this package

The remediation package is built from the current clean worktree without copying the uploaded `.git/` directory. A new repository history is created from the remediated tree only.

Old history was not carried into the sanitized package. The package should be treated as a replacement repository root, not as a normal commit on top of the old repository.

## What this fixes

- old `docs/research/*` records are absent from the new tree and absent from the new package history
- old `src/auditex/research.py` competitor-harvest code is absent from the new tree and absent from the new package history
- old commits and tags from the uploaded repository are not included in the sanitized package
- local `.venv`, `.secrets`, `.pytest_cache`, compiled Python files, and run outputs are excluded

## What this does not fix by itself

- remote hosting providers may keep cached objects, pull requests, releases, forks, or downloaded archives
- anyone who already cloned the old repository may still possess old objects
- legal and forensic review are still external release gates

## Cutover rule

Use this package as a clean repository root. Do not merge it back into the old history.

Preferred cutover:

1. create a new private repository, or delete and recreate the old one if the host and policy allow it
2. push the sanitized repository as the initial history
3. recreate only clean tags/releases
4. rotate any exposed secrets independently; history cleanup does not revoke credentials

If the same remote URL must be reused, force-push this sanitized history and then remove old tags/releases. Confirm the host has garbage-collected unreachable objects before assuming the old history is inaccessible.
