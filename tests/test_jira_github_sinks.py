from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "ticket-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-ticket-test"


def test_send_notification_jira_dry_run_returns_planned(run_dir: Path) -> None:
    from auditex.notify import send_notification

    result = send_notification(run_dir=str(run_dir), sink="jira", dry_run=True)
    assert result["status"] == "planned"
    assert result["sink"] == "jira"


def test_send_notification_github_dry_run_returns_planned(run_dir: Path) -> None:
    from auditex.notify import send_notification

    result = send_notification(run_dir=str(run_dir), sink="github", dry_run=True)
    assert result["status"] == "planned"
    assert result["sink"] == "github"


def test_send_notification_jira_blocks_without_env(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.notify import send_notification

    for var in ("AUDITEX_JIRA_BASE_URL", "AUDITEX_JIRA_PROJECT_KEY", "AUDITEX_JIRA_EMAIL", "AUDITEX_JIRA_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    result = send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)
    assert result["status"] == "blocked"
    assert "AUDITEX_JIRA_BASE_URL" in result["reason"]


def test_send_notification_github_blocks_without_env(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.notify import send_notification

    for var in ("AUDITEX_GITHUB_TOKEN", "AUDITEX_GITHUB_REPO"):
        monkeypatch.delenv(var, raising=False)
    result = send_notification(run_dir=str(run_dir), sink="github", dry_run=False)
    assert result["status"] == "blocked"
    assert "AUDITEX_GITHUB_TOKEN" in result["reason"] or "AUDITEX_GITHUB_REPO" in result["reason"]


def test_send_notification_jira_posts_issue(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_JIRA_BASE_URL", "https://example.atlassian.net")
    monkeypatch.setenv("AUDITEX_JIRA_PROJECT_KEY", "AUDIT")
    monkeypatch.setenv("AUDITEX_JIRA_EMAIL", "bot@example.com")
    monkeypatch.setenv("AUDITEX_JIRA_API_TOKEN", "token-123")

    captured: dict[str, Any] = {}

    class _FakePost:
        status_code = 201
        text = '{"key": "AUDIT-99"}'

        def json(self) -> dict[str, Any]:
            return {"key": "AUDIT-99"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, auth: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["auth"] = auth
        return _FakePost()

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)

    assert result["status"] == "sent"
    assert result["http_status"] == 201
    assert result["issue_key"] == "AUDIT-99"
    assert captured["url"].endswith("/rest/api/3/issue")
    assert captured["json"]["fields"]["project"]["key"] == "AUDIT"
    assert captured["auth"] == ("bot@example.com", "token-123")


def test_send_notification_github_posts_issue(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_GITHUB_TOKEN", "ghp_token")
    monkeypatch.setenv("AUDITEX_GITHUB_REPO", "magrathean-uk/auditex")

    captured: dict[str, Any] = {}

    class _FakePost:
        status_code = 201
        text = '{"number": 42, "html_url": "https://github.com/x/y/issues/42"}'

        def json(self) -> dict[str, Any]:
            return {"number": 42, "html_url": "https://github.com/x/y/issues/42"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakePost()

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)

    assert result["status"] == "sent"
    assert result["http_status"] == 201
    assert result["issue_number"] == 42
    assert captured["url"] == "https://api.github.com/repos/magrathean-uk/auditex/issues"
    assert "title" in captured["json"]
    assert captured["headers"]["Authorization"] == "Bearer ghp_token"
