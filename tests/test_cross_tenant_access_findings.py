from __future__ import annotations

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot(default: dict[str, object] | None = None, partners: list[dict[str, object]] | None = None) -> dict[str, object]:
    payloads = {
        "cross_tenant_access": {
            "crossTenantAccessPolicy": {"value": [{"displayName": "X"}]},
            "defaultPolicy": {"value": [default] if default else []},
            "partnerConfigurations": {"value": partners or []},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_default_and_partner_records() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "allowed",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "blocked",
            "inbound_trust_mfa_accepted": True,
        },
        partners=[
            {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "blocked",
                "is_service_provider": False,
            }
        ],
    )

    assert snapshot.get("cross_tenant_default_objects") is not None
    assert snapshot.get("cross_tenant_partner_objects") is not None


def test_findings_flag_default_b2b_direct_connect_open() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "allowed",
            "inbound_trust_mfa_accepted": False,
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "cross_tenant_access:default:b2b_direct_connect_inbound_open"), None
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_partner_inbound_trust_without_mfa() -> None:
    snapshot = _snapshot(
        partners=[
            {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "blocked",
                "inbound_trust_mfa_accepted": False,
                "is_service_provider": False,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (
            f
            for f in findings
            if f["id"]
            == "cross_tenant_access:partner:11111111-1111-1111-1111-111111111111:b2b_direct_connect_no_mfa"
        ),
        None,
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_skip_microsoft_service_provider_partner() -> None:
    snapshot = _snapshot(
        partners=[
            {
                "tenant_id": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "allowed",
                "inbound_trust_mfa_accepted": False,
                "is_service_provider": True,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    partner_findings = [f for f in findings if "cross_tenant_access:partner" in f["id"]]
    assert partner_findings == []
