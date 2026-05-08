from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from azure_tenant_audit.collectors.app_credentials import AppCredentialsCollector


def _iso(delta_days: int) -> str:
    return (datetime.now(tz=timezone.utc) + timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _FakeClient:
    def __init__(
        self,
        applications: list[dict[str, Any]] | None = None,
        service_principals: list[dict[str, Any]] | None = None,
        federated: dict[str, list[dict[str, Any]]] | None = None,
        owners: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._applications = applications or []
        self._service_principals = service_principals or []
        self._federated = federated or {}
        self._owners = owners or {}
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {})))
        if path == "/applications":
            return list(self._applications)
        if path == "/servicePrincipals":
            return list(self._service_principals)
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        if path.startswith("/applications/") and path.endswith("/federatedIdentityCredentials"):
            app_id = path.split("/")[2]
            return {"value": list(self._federated.get(app_id, []))}
        if path.startswith("/applications/") and path.endswith("/owners"):
            app_id = path.split("/")[2]
            return {"value": list(self._owners.get(app_id, []))}
        if path.startswith("/servicePrincipals/") and path.endswith("/owners"):
            sp_id = path.split("/")[2]
            return {"value": list(self._owners.get(sp_id, []))}
        raise AssertionError(f"unexpected path: {path}")


def test_collector_collects_application_credentials_and_redirect_uris() -> None:
    applications = [
        {
            "id": "app-1",
            "displayName": "Build Bot",
            "appId": "11111111-1111-1111-1111-111111111111",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [
                {"keyId": "secret-1", "endDateTime": _iso(15), "displayName": "rotate me"}
            ],
            "keyCredentials": [
                {"keyId": "cert-1", "endDateTime": _iso(400)}
            ],
            "web": {"redirectUris": ["https://contoso.com/callback", "http://example.com/callback"]},
            "spa": {"redirectUris": []},
            "publicClient": {"redirectUris": []},
        }
    ]
    client = _FakeClient(applications=applications, owners={"app-1": [{"id": "owner-1"}]})

    collector = AppCredentialsCollector()
    result = collector.run({"client": client, "top": 100})

    assert result.status == "ok"
    apps = result.payload["applicationCredentials"]["value"]
    assert apps[0]["id"] == "app-1"
    assert apps[0]["password_credentials"][0]["key_id"] == "secret-1"
    assert any(uri["scheme"] == "http" for uri in apps[0]["redirect_uris"])
    assert apps[0]["owner_count"] == 1


def test_collector_records_federated_identity_credentials() -> None:
    applications = [
        {
            "id": "app-1",
            "displayName": "GitHub Actions OIDC",
            "appId": "1",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "keyCredentials": [],
            "web": {"redirectUris": []},
        }
    ]
    federated = {
        "app-1": [
            {
                "id": "fed-1",
                "name": "github-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:contoso/app:ref:refs/heads/main",
                "audiences": ["api://AzureADTokenExchange"],
            }
        ]
    }
    client = _FakeClient(applications=applications, federated=federated, owners={"app-1": []})

    collector = AppCredentialsCollector()
    result = collector.run({"client": client, "top": 100})

    apps = result.payload["applicationCredentials"]["value"]
    assert apps[0]["federated_credentials"][0]["issuer"] == "https://token.actions.githubusercontent.com"


def test_collector_handles_graph_failure_gracefully() -> None:
    from azure_tenant_audit.graph import GraphError

    class _FailingClient:
        def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
            raise GraphError("forbidden", status=403, request=path)

        def get_json(self, *args, **kwargs):  # noqa: ANN001
            raise GraphError("forbidden", status=403, request="generic")

    collector = AppCredentialsCollector()
    result = collector.run({"client": _FailingClient(), "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert any(row["status"] == "failed" and row["error_class"] == "insufficient_permissions" for row in coverage)


def test_collector_skips_owner_calls_when_missing_get_json() -> None:
    applications = [
        {"id": "app-1", "displayName": "App", "appId": "1", "signInAudience": "AzureADMyOrg", "passwordCredentials": [], "keyCredentials": [], "web": {"redirectUris": []}}
    ]

    class _GetAllOnly:
        def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
            if path == "/applications":
                return applications
            if path == "/servicePrincipals":
                return []
            raise AssertionError(path)

    collector = AppCredentialsCollector()
    result = collector.run({"client": _GetAllOnly(), "top": 100})

    apps = result.payload["applicationCredentials"]["value"]
    assert apps[0]["owner_count"] is None
    assert apps[0]["federated_credentials"] == []
