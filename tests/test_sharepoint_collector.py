from __future__ import annotations

from azure_tenant_audit.collectors.sharepoint import SharePointCollector


class _SharePointClient:
    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        if path == "/admin/sharepoint/settings":
            return {"isLoopEnabled": True}
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001
        if path == "/sites":
            assert params["$top"] == "150"
            return [{"id": "site-1", "webUrl": "https://contoso.sharepoint.com/sites/site-1"}]
        raise AssertionError(f"unexpected path: {path}")


def test_sharepoint_collector_collects_settings_and_sites() -> None:
    collector = SharePointCollector()
    result = collector.run({"client": _SharePointClient(), "top": 150, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["sharePointSettings"]["isLoopEnabled"] is True
    assert result.payload["sites"]["value"][0]["id"] == "site-1"
