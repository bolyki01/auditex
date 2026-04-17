from __future__ import annotations

from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import GRAPH_ROOT, GraphClient


def _client() -> GraphClient:
    return GraphClient(
        AuthConfig(
            tenant_id="tenant-1",
            client_id="client-1",
            auth_mode="access_token",
            access_token="token",
        )
    )


def test_iter_pages_follows_next_link(monkeypatch) -> None:
    client = _client()
    next_link = f"{GRAPH_ROOT}/users?$skiptoken=abc"
    payloads = {
        f"{GRAPH_ROOT}/users": {
            "value": [{"id": "user-1"}],
            "@odata.nextLink": next_link,
        },
        next_link: {
            "value": [{"id": "user-2"}],
        },
    }

    def _fake_get_json(path, params=None, full_url=False):  # noqa: ANN001, ARG001
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        return payloads[url]

    monkeypatch.setattr(client, "get_json", _fake_get_json)

    pages = list(client.iter_pages("/users", params={"$top": "1"}))
    assert len(pages) == 2
    assert pages[0]["value"][0]["id"] == "user-1"
    assert pages[1]["value"][0]["id"] == "user-2"


def test_iter_items_honors_global_result_limit(monkeypatch) -> None:
    client = _client()
    next_link = f"{GRAPH_ROOT}/users?$skiptoken=abc"
    payloads = {
        f"{GRAPH_ROOT}/users": {
            "value": [{"id": "user-1"}, {"id": "user-2"}],
            "@odata.nextLink": next_link,
        },
        next_link: {
            "value": [{"id": "user-3"}, {"id": "user-4"}],
        },
    }

    def _fake_get_json(path, params=None, full_url=False):  # noqa: ANN001, ARG001
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        return payloads[url]

    monkeypatch.setattr(client, "get_json", _fake_get_json)

    rows = list(client.iter_items("/users", params={"$top": "2"}, result_limit=3))
    assert [row["id"] for row in rows] == ["user-1", "user-2", "user-3"]
