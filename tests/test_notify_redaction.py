"""E4: Teams / Slack secret redaction.

Webhook bodies cross process boundaries into long-lived stores (chat
history, third-party loggers, email digests). Anything credential-
shaped that lands there might never be rotated. Test the redaction
pass with adversarial inputs that simulate real-world credential
leaks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.notify import _redact_string, _redact_value


def test_bearer_token_in_string_is_redacted() -> None:
    s = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdC1wYXlsb2Fk.signature_here"
    redacted = _redact_string(s)
    assert "Bearer " in redacted
    assert "[REDACTED]" in redacted
    assert "eyJ" not in redacted or "[REDACTED-JWT]" in redacted
    assert "signature_here" not in redacted


def test_jwt_anywhere_in_payload_is_redacted() -> None:
    s = "the token is eyJabcdefghijklmnop.qrstuvwxyz0123456789.signature_part rest of message"
    redacted = _redact_string(s)
    assert "[REDACTED-JWT]" in redacted
    assert "qrstuvwxyz" not in redacted


def test_long_base64_blob_is_redacted_as_blob() -> None:
    """DSC blob fragments / encrypted PFX exports are typically long
    base64. 200+ chars is the threshold."""
    long_blob = "A" * 220 + "=="
    redacted = _redact_string(f"prefix {long_blob} suffix")
    assert "[REDACTED-BLOB]" in redacted
    assert "AAAAAAAAAA" not in redacted


def test_short_base64_strings_pass_through() -> None:
    """Short ID-like strings must NOT be redacted as blobs."""
    short = "abc123def456ghi789jkl"
    redacted = _redact_string(short)
    assert redacted == short


def test_dict_value_under_sensitive_key_is_replaced() -> None:
    payload = {"client_secret": "abc123", "tenant_name": "contoso"}
    redacted = _redact_value(payload)
    assert redacted["client_secret"] == "[REDACTED]"
    assert redacted["tenant_name"] == "contoso"


def test_dict_value_under_non_sensitive_key_keeps_unredacted_text() -> None:
    payload = {"description": "Normal text without tokens"}
    redacted = _redact_value(payload)
    assert redacted["description"] == "Normal text without tokens"


def test_nested_dict_with_token_in_value_is_redacted() -> None:
    payload = {
        "evidence": {
            "raw": "Authorization: Bearer eyJabcdefghijklmnop.qrstuvwxyz123456789.signature",
            "ok_field": "no secret here",
        }
    }
    redacted = _redact_value(payload)
    assert "[REDACTED" in redacted["evidence"]["raw"]
    assert "Bearer eyJ" not in redacted["evidence"]["raw"]
    assert redacted["evidence"]["ok_field"] == "no secret here"


def test_list_of_findings_redacts_each_element() -> None:
    findings = [
        {"id": "f1", "evidence": {"client_secret": "leaked-secret-xyz"}},
        {"id": "f2", "title": "Bearer abc12345abc"},
    ]
    redacted = _redact_value(findings)
    assert redacted[0]["evidence"]["client_secret"] == "[REDACTED]"
    assert "[REDACTED]" in redacted[1]["title"]


def test_sensitive_key_with_none_or_empty_value_is_left_alone() -> None:
    """Don't replace empty / None — that would obscure ``not set``
    diagnostics in operator-facing output."""
    payload = {"client_secret": None, "secret_text": ""}
    redacted = _redact_value(payload)
    assert redacted["client_secret"] is None
    assert redacted["secret_text"] == ""


# ----- End-to-end: webhook body never carries leaked secrets -----


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "redaction-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-redaction-test"


def test_webhook_body_redacts_planted_secrets_end_to_end(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plant adversarial secrets into the action_plan and verify the
    body that hits the webhook does NOT contain them."""
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_TEAMS_WEBHOOK_URL", "https://example.test/webhook")
    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200
        text = "ok"

    def _fake_post(url: str, json: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        captured["body"] = json
        return _FakeResponse()

    # Inject a payload-builder stub that returns adversarial content.
    leaked_jwt = "eyJabcdefghijklmnop.qrstuvwxyz1234567890.this_is_signature_part"
    leaked_secret = "S3cr3tBearer~ABC123-leaked!"
    leaked_blob = "B" * 220
    adversarial_payload = {
        "tenant_name": "contoso",
        "overall_status": "ok",
        "finding_count": 1,
        "open_count": 0,
        "blocker_count": 0,
        "action_plan": [
            {
                "id": "f1",
                "title": "Finding with Authorization: Bearer " + leaked_secret,
                "evidence": {
                    "client_secret": "literally-a-secret",
                    "raw_jwt": leaked_jwt,
                    "dsc_export": leaked_blob,
                },
            }
        ],
    }
    monkeypatch.setattr(notify_module, "_build_payload", lambda run_dir: adversarial_payload)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    notify_module.send_notification(run_dir=str(run_dir), sink="teams", dry_run=False)

    body_str = json.dumps(captured["body"])
    # None of the planted secrets should appear in the wire body.
    assert leaked_jwt not in body_str
    assert leaked_blob not in body_str
    assert "literally-a-secret" not in body_str
    # The Bearer header text-form must be redacted in the title.
    assert leaked_secret not in body_str
    # And the redaction markers should be present so an operator reading
    # the chat sees that something was scrubbed.
    assert "REDACTED" in body_str


def test_webhook_body_preserves_normal_findings_text(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanity: normal payloads are NOT mutated beyond the redactions."""
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_TEAMS_WEBHOOK_URL", "https://example.test/webhook")
    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200
        text = "ok"

    def _fake_post(url: str, json: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured["body"] = json
        return _FakeResponse()

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    notify_module.send_notification(run_dir=str(run_dir), sink="teams", dry_run=False)

    body_str = json.dumps(captured["body"])
    assert "contoso" in body_str  # tenant name passes through
    assert "Auditex" in body_str  # framing text passes through
