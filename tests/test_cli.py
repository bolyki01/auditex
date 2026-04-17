from __future__ import annotations

import json
from pathlib import Path
import sys

from azure_tenant_audit import cli
from azure_tenant_audit.collectors.base import CollectorResult


class _IdentityCollector:
    def __init__(self, name: str = "identity") -> None:
        self.name = name

    def run(self, _context: dict) -> CollectorResult:
        return CollectorResult(
            name=self.name,
            status="ok",
            item_count=1,
            message="ok",
            payload={"value": [{"id": "1"}]},
        )


def test_offline_creates_bundle(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = {
        "identity": {"value": [{"id": "1"}]},
        "security": {"value": [{"id": "2"}, {"id": "3"}]},
    }
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(sample_path, tmp_path, "contoso", "run1")
    assert rc == 0

    output_dir = tmp_path / "contoso-run1"
    assert output_dir.exists()
    assert (output_dir / "run-manifest.json").exists()
    assert (output_dir / "summary.json").exists()
    assert (output_dir / "summary.md").exists()
    assert (output_dir / "raw" / "sample_input.json").exists()


def test_main_offline_preserves_plane_and_time_window(tmp_path: Path) -> None:
    sample = {"identity": {"value": [{"id": "1"}]}}
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = cli.main(
        [
            "--tenant-name",
            "contoso",
            "--offline",
            "--sample",
            str(sample_path),
            "--out",
            str(tmp_path),
            "--run-name",
            "offline-plane-test",
            "--auditor-profile",
            "global-reader",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
        ]
    )
    assert rc == 0

    manifest = json.loads((tmp_path / "contoso-offline-plane-test" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["auditor_profile"] == "global-reader"
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"


def test_offline_missing_sample_fails(tmp_path: Path) -> None:
    rc = cli.run_offline(
        tmp_path / "missing.json",
        tmp_path,
        "contoso",
        "run1",
    )
    assert rc == 2


def test_interactive_defaults_tenant_id_to_organizations(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth):
            self.tenant_id = auth.tenant_id

    captured = {}
    class _FakeClientFactory:
        def __new__(cls, auth, **kwargs):  # noqa: ANN001
            captured["tenant_id"] = auth.tenant_id
            return _FakeClient(auth)

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--interactive",
            "--client-id",
            "app-id",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", _FakeClientFactory)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _IdentityCollector()})
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    rc = cli.run_live(args)

    assert rc == 0
    assert captured["tenant_id"] == "organizations"


def test_run_live_logs_run_events(tmp_path: Path, monkeypatch) -> None:
    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
                coverage=[{"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1}],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

    def _fake_client_factory(auth, **kwargs):
        return _FakeClient(auth, audit_event=kwargs.get("audit_event"))

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "identity",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", _fake_client_factory)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    rc = cli.run_live(args)
    assert rc == 0
    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs, "run output directory should exist"
    output_dir = output_dirs[0]
    log_path = output_dir / "audit-log.jsonl"
    assert log_path.exists()
    events = [json.loads(line)["event"] for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert "run.started" in events
    assert "collector.started" in events
    assert "collector.finished" in events
    assert "run.complete" in events

    output_dir = output_dirs[0]
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["coverage_count"] == 1
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"
    assert (output_dir / "coverage.json").exists()
    assert (output_dir / "index" / "coverage.jsonl").exists()


def test_run_live_writes_diagnostics(tmp_path: Path, monkeypatch) -> None:
    class _FailingCollector:
        name = "security"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=0,
                message="security collector failed",
                error="security collector failed",
                payload={"securityAlerts": {"error": "forbidden"}},
                coverage=[
                    {
                        "collector": "security",
                        "type": "graph",
                        "name": "securityAlerts",
                        "endpoint": "/security/alerts",
                        "status": "failed",
                        "item_count": 0,
                        "error_class": "insufficient_permissions",
                        "error": "Forbidden",
                    }
                ],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth))
    monkeypatch.setattr(cli, "REGISTRY", {"security": _FailingCollector()})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "security",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 1
    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    output_dir = output_dirs[0]
    diagnostics_path = output_dir / "diagnostics.json"
    assert diagnostics_path.exists()
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert isinstance(diagnostics, list)
    assert diagnostics
    assert diagnostics[0]["collector"] == "security"
    assert diagnostics[0]["recommendations"]["required_graph_scopes"]


def test_interactive_without_client_id_falls_back_to_azure_cli_token(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

        def get_json(self, path):
            assert path == "/me"
            return {
                "displayName": "Fallback User",
                "userPrincipalName": "fallback@tenant.local",
                "id": "fallback-user",
            }

        def get_all(self, path, params=None):
            assert path == "/me/memberOf/microsoft.graph.directoryRole"
            return []

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--interactive",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "fallback-token")
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, audit_event=kwargs.get("audit_event")))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _IdentityCollector()})
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "azure_cli"


def test_run_live_with_azure_cli_token_uses_azure_cli_mode(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    def _fake_client_factory(auth, **kwargs):
        return _FakeClient(auth)

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", _fake_client_factory)
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    monkeypatch.setattr(sys, "argv", ["audit", "--tenant-name", "acme", "--tenant-id", "t-123", "--use-azure-cli-token", "--collectors", "identity", "--out", str(tmp_path)])
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "azure_cli"


def test_command_line_redaction_in_manifest_when_access_token_is_on_command_line(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    secret = "super-secret-token"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python3",
            "-m",
            "azure_tenant_audit",
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--access-token",
            secret,
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ],
    )
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--access-token",
            secret,
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0


def test_azure_cli_run_captures_session_context(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth
            self.audit_event = audit_event

        def get_json(self, path):
            assert path == "/me"
            return {
                "displayName": "Gyorgy Bolyki",
                "userPrincipalName": "bolyki@bolyki.eu",
                "id": "user-123",
            }

        def get_all(self, path, params=None):
            assert path == "/me/memberOf/microsoft.graph.directoryRole"
            return [
                {"displayName": "Global Administrator"},
                {"displayName": "Global Reader"},
            ]

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["session_context"]["user_principal_name"] == "bolyki@bolyki.eu"
    assert manifest["session_context"]["roles"] == ["Global Administrator", "Global Reader"]


def test_scrub_command_line_redacts_tokens() -> None:
    scrubbed = cli._scrub_command_line(
        [
            "python3",
            "--tenant-name",
            "acme",
            "--access-token",
            "super-secret-token",
            "--client-secret=foo",
            "--collectors=identity",
        ]
    )
    assert scrubbed == [
        "python3",
        "--tenant-name",
        "acme",
        "--access-token",
        "***redacted***",
        "--client-secret=***redacted***",
        "--collectors=identity",
    ]
