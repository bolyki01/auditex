from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit import cli
from auditex import cli as auditex_cli


def test_parser_accepts_collector_preset() -> None:
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--offline",
            "--collector-preset",
            "identity-only",
        ]
    )

    assert args.collector_preset == "identity-only"


def test_collector_preset_resolves_before_profile_defaults(tmp_path: Path) -> None:
    from azure_tenant_audit.presets import load_collector_presets, resolve_collector_selection

    preset_path = tmp_path / "collector-presets.json"
    preset_path.write_text(
        json.dumps(
            {
                "presets": {
                    "identity-only": {
                        "description": "Identity only",
                        "include": ["identity", "security"],
                        "exclude": ["security"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    presets = load_collector_presets(preset_path)
    resolved = resolve_collector_selection(
        available=["identity", "security", "sharepoint"],
        profile_default_collectors=("sharepoint",),
        preset_name="identity-only",
        presets=presets,
    )

    assert resolved == ["identity"]


def test_explicit_collectors_override_preset(tmp_path: Path) -> None:
    from azure_tenant_audit.presets import load_collector_presets, resolve_collector_selection

    preset_path = tmp_path / "collector-presets.json"
    preset_path.write_text(
        json.dumps({"presets": {"identity-only": {"include": ["identity"]}}}),
        encoding="utf-8",
    )

    presets = load_collector_presets(preset_path)
    resolved = resolve_collector_selection(
        available=["identity", "security", "sharepoint"],
        profile_default_collectors=("sharepoint",),
        preset_name="identity-only",
        presets=presets,
        explicit_collectors=["security"],
        excluded_collectors=["sharepoint"],
    )

    assert resolved == ["security"]


def test_rule_inventory_lists_sorted_rows(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_rule_inventory",
        lambda **_: [
            {"name": "zeta.rule", "tags": ["security"]},
            {"name": "alpha.rule", "tags": ["identity"]},
        ],
    )

    rc = auditex_cli.main(["rules", "inventory"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["name"] for row in payload["rules"]] == ["alpha.rule", "zeta.rule"]


def test_rule_inventory_filters_by_tag(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_rule_inventory",
        lambda **_: [{"name": "alpha.rule", "tags": ["identity"]}],
    )

    rc = auditex_cli.main(["rules", "inventory", "--tag", "identity"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["rules"][0]["name"] == "alpha.rule"
