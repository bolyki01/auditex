"""F1 regression: every ``uses:`` in a GitHub Actions workflow must be
pinned to a full 40-character commit SHA, per OpenSSF Scorecard
guidance. A bare-tag pin (``@v3``) is a security hole — a malicious
maintainer of the action can re-tag to a different commit at any
moment.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW_DIR = _REPO / ".github" / "workflows"
_USES_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")


def _workflow_files() -> list[Path]:
    if not _WORKFLOW_DIR.exists():
        return []
    return sorted(p for p in _WORKFLOW_DIR.glob("*.yml")) + sorted(
        p for p in _WORKFLOW_DIR.glob("*.yaml")
    )


@pytest.fixture
def workflow_paths() -> list[Path]:
    paths = _workflow_files()
    if not paths:
        pytest.skip("no GitHub Actions workflows in this repo")
    return paths


def test_every_workflow_uses_clause_is_sha_pinned(workflow_paths: list[Path]) -> None:
    violations: list[str] = []
    for path in workflow_paths:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("- uses:") and not stripped.startswith("uses:"):
                continue
            after_uses = stripped.split("uses:", 1)[1].strip()
            ref_part = after_uses.split("#", 1)[0].strip()
            if "@" not in ref_part:
                violations.append(f"{path.name}:{lineno}: no @ref in `uses:` value")
                continue
            _, ref = ref_part.rsplit("@", 1)
            ref = ref.strip(' "\'')
            if after_uses.startswith("./") or after_uses.startswith("docker://"):
                continue
            if not _USES_SHA_PATTERN.match(ref):
                violations.append(
                    f"{path.name}:{lineno}: `uses:` ref ``{ref}`` is not a 40-char SHA"
                )
    assert not violations, (
        "GitHub Actions workflows have un-pinned `uses:` clauses (OpenSSF "
        "Scorecard pinned-dependencies finding):\n  " + "\n  ".join(violations)
    )


def test_every_sha_pin_has_a_version_comment(workflow_paths: list[Path]) -> None:
    violations: list[str] = []
    tag_pattern = re.compile(r"v?\d+(?:\.\d+)*")
    for path in workflow_paths:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not (stripped.startswith("- uses:") or stripped.startswith("uses:")):
                continue
            after_uses = stripped.split("uses:", 1)[1].strip()
            if after_uses.startswith("./") or after_uses.startswith("docker://"):
                continue
            ref_part, _, comment = after_uses.partition("#")
            ref_part = ref_part.strip()
            if "@" not in ref_part:
                continue
            _, ref = ref_part.rsplit("@", 1)
            if not _USES_SHA_PATTERN.match(ref.strip(' "\'')):
                continue
            if not tag_pattern.search(comment):
                violations.append(
                    f"{path.name}:{lineno}: SHA-pinned `uses:` lacks `# vX.Y.Z` version comment"
                )
    assert not violations, (
        "Every SHA-pinned `uses:` should carry a trailing version "
        "comment so reviewers can spot stale pins:\n  " + "\n  ".join(violations)
    )
