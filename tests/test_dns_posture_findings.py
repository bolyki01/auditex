from __future__ import annotations

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot_with_dns(value: list[dict[str, object]]) -> dict[str, object]:
    payloads = {
        "dns_posture": {
            "domains": {"value": []},
            "domainPosture": {"value": value},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_dns_posture_records() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": True, "policy": "reject"},
                "dkim": {"selectors_present": ["selector1", "selector2"], "selectors_missing": []},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    section = snapshot.get("dns_posture_objects")
    assert section is not None
    assert len(section["records"]) == 1
    record = section["records"][0]
    assert record["domain"] == "contoso.com"
    assert record["spf_present"] is True
    assert record["dmarc_present"] is True
    assert record["dmarc_policy"] == "reject"


def test_findings_flag_missing_spf_for_custom_domain() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": False},
                "dmarc": {"present": True, "policy": "reject"},
                "dkim": {"selectors_present": ["selector1", "selector2"], "selectors_missing": []},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    spf_finding = next((f for f in findings if f["id"] == "dns_posture:contoso.com:spf_missing"), None)
    assert spf_finding is not None
    assert spf_finding["severity"] == "high"
    assert spf_finding["category"] == "mail_flow"


def test_findings_flag_dmarc_p_none_as_medium() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": True, "policy": "none"},
                "dkim": {"selectors_present": ["selector1", "selector2"], "selectors_missing": []},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "dns_posture:contoso.com:dmarc_monitor_only"), None)
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_flag_missing_dmarc_as_high() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": False},
                "dkim": {"selectors_present": ["selector1"], "selectors_missing": ["selector2"]},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "dns_posture:contoso.com:dmarc_missing"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_spf_softfail_or_neutral() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": True, "all_qualifier": "+"},
                "dmarc": {"present": True, "policy": "reject"},
                "dkim": {"selectors_present": ["selector1", "selector2"], "selectors_missing": []},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "dns_posture:contoso.com:spf_passthrough"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_missing_dkim_selectors_for_custom_domain() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.com",
                "managed_by_microsoft": False,
                "spf": {"present": True, "all_qualifier": "-"},
                "dmarc": {"present": True, "policy": "reject"},
                "dkim": {"selectors_present": [], "selectors_missing": ["selector1", "selector2"]},
                "mta_sts": {"dns_present": True},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "dns_posture:contoso.com:dkim_missing"), None)
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_skip_microsoft_managed_domains() -> None:
    snapshot = _snapshot_with_dns(
        [
            {
                "domain": "contoso.onmicrosoft.com",
                "managed_by_microsoft": True,
                "spf": {"present": False},
                "dmarc": {"present": False},
                "dkim": {"selectors_present": [], "selectors_missing": ["selector1", "selector2"]},
                "mta_sts": {"dns_present": False},
                "bimi": {"present": False},
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    domain_findings = [f for f in findings if "dns_posture:contoso.onmicrosoft.com" in f["id"]]
    assert domain_findings == []
