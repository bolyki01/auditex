from __future__ import annotations

from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.collectors.base import _classify_graph_error
from azure_tenant_audit.graph import GraphClient, GraphError


class _FakeResponse:
    def __init__(self, status_code: int, body, *, headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.url = "https://graph.microsoft.com/v1.0/me"

    @property
    def text(self) -> str:
        if isinstance(self._body, str):
            return self._body
        return str(self._body)

    def json(self):
        return self._body


def test_graph_error_includes_http_status_and_code(monkeypatch) -> None:
    auth = AuthConfig(
        tenant_id="t-1",
        client_id="c-1",
        auth_mode="access_token",
        access_token="x",
    )
    client = GraphClient(auth)

    def _request(method, url, **kwargs):  # noqa: ARG001
        return _FakeResponse(
            403,
            {
                "error": {
                    "code": "Authorization_RequestDenied",
                    "message": "Access denied due to insufficient privileges",
                }
            },
        )

    monkeypatch.setattr(client, "_request", _request)

    exc = None
    try:
        client.get_json("/me")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.status == 403
    assert exc.error_code == "Authorization_RequestDenied"
    assert "Access denied" in str(exc)


def test_classify_graph_error_known_statuses() -> None:
    error = GraphError("AADSTS500113: No reply address is registered for the application.", status=400)
    error_class, _ = _classify_graph_error(error)
    assert error_class == "app_missing_reply_url"

    forbidden = GraphError("insufficient privileges", status=403)
    error_class, _ = _classify_graph_error(forbidden)
    assert error_class == "insufficient_permissions"


def test_get_all_requires_dict_payload(monkeypatch) -> None:
    auth = AuthConfig(
        tenant_id="t-1",
        client_id="c-1",
        auth_mode="access_token",
        access_token="x",
    )
    client = GraphClient(auth)

    def _request(method, url, **kwargs):  # noqa: ARG001
        return _FakeResponse(200, [1, 2, 3])

    monkeypatch.setattr(client, "_request", _request)

    exc = None
    try:
        client.get_all("/users")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.request == "https://graph.microsoft.com/v1.0/users"
