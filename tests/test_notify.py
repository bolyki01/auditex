from __future__ import annotations

import json
from pathlib import Path

from auditex.notify import send_notification


def _write_run_bundle(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "reports").mkdir(exist_ok=True)
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps(
            {
                "summary": {
                    "tenant_name": "acme",
                    "overall_status": "partial",
                    "finding_count": 2,
                    "blocker_count": 1,
                    "open_count": 1,
                    "accepted_count": 1,
                },
                "findings": [],
                "action_plan": [{"id": "finding-1", "title": "Fix sharing"}],
                "evidence_paths": [],
            }
        ),
        encoding="utf-8",
    )


def test_send_notification_builds_dry_run_payload(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)

    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=True)

    assert result["sink"] == "teams"
    assert result["dry_run"] is True
    assert result["payload"]["tenant_name"] == "acme"
    assert result["payload"]["open_count"] == 1
    assert result["payload"]["action_plan"][0]["id"] == "finding-1"


def test_send_notification_posts_to_webhook_when_execute_enabled(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    seen: dict[str, object] = {}

    class _Response:
        status_code = 200
        text = "ok"

    def _fake_post(url, json=None, timeout=None):  # noqa: ANN001
        seen["url"] = url
        seen["json"] = json
        seen["timeout"] = timeout
        return _Response()

    monkeypatch.setenv("AUDITEX_TEAMS_WEBHOOK_URL", "https://hooks.example.test/teams")
    monkeypatch.setattr("auditex.notify.requests.post", _fake_post)

    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=False)

    assert result["status"] == "sent"
    assert seen["url"] == "https://hooks.example.test/teams"
    assert seen["json"]["text"]
