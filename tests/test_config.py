from __future__ import annotations

from pathlib import Path

from azure_tenant_audit.config import CollectorConfig, RunConfig


def test_selected_collectors_respects_include_exclude():
    config_path = Path("configs/collector-definitions.json")
    cfg = CollectorConfig.from_path(config_path)
    run = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        collectors=["identity", "security"],
        excluded_collectors=["security"],
        include_exchange=True,
    )
    available = ["identity", "security", "intune", "teams", "exchange"]
    selected = run.selected_collectors(available)
    assert selected == ["identity"]


def test_selected_collectors_includes_exchange_only_when_explicitly_requested():
    cfg = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    run_default = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        include_exchange=False,
    )
    available = [name for name in cfg.default_order if cfg.collectors[name].enabled]
    available.append("exchange")
    selected_without_exchange = run_default.selected_collectors(available)
    assert "exchange" not in selected_without_exchange

    run_include_exchange = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        include_exchange=True,
    )
    selected_with_exchange = run_include_exchange.selected_collectors(available)
    assert selected_with_exchange[-1] == "exchange"
    assert "exchange" in selected_with_exchange
