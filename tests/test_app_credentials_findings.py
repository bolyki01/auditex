from __future__ import annotations

from datetime import datetime, timedelta, timezone

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _iso(delta_days: int) -> str:
    return (datetime.now(tz=timezone.utc) + timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snapshot_with_apps(apps: list[dict[str, object]]) -> dict[str, object]:
    payloads = {
        "app_credentials": {
            "applicationCredentials": {"value": apps},
            "servicePrincipalCredentials": {"value": []},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_application_credential_records() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(10)}],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://example.com/callback", "scheme": "http"}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    section = snapshot.get("application_credential_objects")
    assert section is not None
    assert section["records"][0]["display_name"] == "Build Bot"


def test_findings_flag_expiring_secret_high() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(10)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:secret_expiring"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_expired_secret_critical() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(-5)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:secret_expired"), None)
    assert finding is not None
    assert finding["severity"] == "critical"


def test_findings_flag_http_redirect_uri() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://example.com/callback", "scheme": "http"}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:redirect_insecure"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_skip_localhost_http() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Dev",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://localhost:8080/callback", "scheme": "http", "is_localhost": True}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    redirect_findings = [f for f in findings if "redirect_insecure" in f["id"]]
    assert redirect_findings == []


def test_findings_flag_no_owners() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Orphan App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(365)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 0,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:no_owner"), None)
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_flag_multi_tenant_audience() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Wide App",
                "app_id": "1",
                "sign_in_audience": "AzureADMultipleOrgs",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:multi_tenant_audience"), None)
    assert finding is not None
    assert finding["severity"] == "medium"
