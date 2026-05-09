"""Regression: the test session must NOT touch the real secrets dir.

Before tests/conftest.py existed, running ``make test`` could silently
overwrite the developer's ``.secrets/m365-auth.env`` with test fixture
values via the guided-flow path that called
``_persist_local_defaults`` without monkeypatching the env-var override.
"""
from __future__ import annotations

import os
from pathlib import Path

from auditex.auth import default_auth_contexts_path, default_local_auth_env_path


def test_local_auth_env_path_resolves_to_tmp() -> None:
    path = default_local_auth_env_path()
    assert "auditex-test-secrets" in str(path), (
        f"AUDITEX_LOCAL_AUTH_ENV did not redirect to a test tmp dir: {path}"
    )


def test_auth_contexts_path_resolves_to_tmp() -> None:
    path = default_auth_contexts_path()
    assert "auditex-test-secrets" in str(path)


def test_local_auth_env_does_not_resolve_to_repo_secrets_dir() -> None:
    path = default_local_auth_env_path()
    repo_secret = Path(__file__).resolve().parent.parent / ".secrets" / "m365-auth.env"
    cwd_secret = Path.cwd() / ".secrets" / "m365-auth.env"
    assert path != repo_secret
    assert path != cwd_secret


def test_environment_variables_are_set() -> None:
    assert os.environ.get("AUDITEX_LOCAL_AUTH_ENV"), "AUDITEX_LOCAL_AUTH_ENV not set"
    assert os.environ.get("AUDITEX_AUTH_CONTEXTS_PATH"), "AUDITEX_AUTH_CONTEXTS_PATH not set"
