from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import requests
from requests.exceptions import RequestException

from .config import AuthConfig


LOG = logging.getLogger(__name__)
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
TOKEN_URL_TEMPLATE = "{authority}{tenant_id}/oauth2/v2.0/token"


class GraphError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        request: str | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.request = request
        self.error_code = error_code


@dataclass
class GraphClient:
    auth: AuthConfig
    session: requests.Session = field(default_factory=requests.Session)
    _token: Optional[str] = None
    audit_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None

    def _emit(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        if self.audit_event is None:
            return
        try:
            self.audit_event(event, message, details)
        except Exception:  # noqa: BLE001
            LOG.exception("Failed to emit audit event.")

    @staticmethod
    def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
        copy = dict(payload)
        if "client_secret" in copy:
            copy["client_secret"] = "***redacted***"
        return copy

    @staticmethod
    def _params_overview(params: Optional[Dict[str, Any]]) -> dict[str, Any]:
        if not params:
            return {}
        return {key: params[key] for key in params.keys()}

    def _token_url(self) -> str:
        return TOKEN_URL_TEMPLATE.format(
            authority=self.auth.authority.rstrip("/") + "/",
            tenant_id=self.auth.tenant_id,
        )

    def _authority(self) -> str:
        tenant_id = self.auth.tenant_id or "organizations"
        return f"{self.auth.authority.rstrip('/')}/{tenant_id}"

    def ensure_token(self) -> str:
        if self._token:
            return self._token
        if self.auth.access_token:
            self._token = self.auth.access_token
            return self._token
        if self.auth.auth_mode == "interactive":
            return self._interactive_token()
        return self._app_token()

    def _app_token(self) -> str:
        if not self.auth.client_secret:
            raise GraphError("No client secret or access token provided.")

        payload = {
            "client_id": self.auth.client_id,
            "client_secret": self.auth.client_secret,
            "scope": self.auth.graph_scope,
            "grant_type": "client_credentials",
        }
        start = time.time()
        self._emit(
            "graph.token.requested",
            "Requesting app token",
            {
                "mode": "client_credentials",
                "token_url": self._token_url(),
                "payload": self._safe_payload(payload),
            },
        )
        try:
            response = self.session.post(
                self._token_url(),
                data=payload,
                timeout=self.auth.timeout_seconds,
            )
        except RequestException as exc:  # noqa: BLE001
            self._emit("graph.token.failed", "Token request raised transport exception", {"error": str(exc)})
            raise GraphError(f"Token request failed: {exc}") from exc
        duration_ms = round((time.time() - start) * 1000, 2)
        if response.status_code >= 400:
            self._emit(
                "graph.token.failed",
                "Token request returned an error response",
                {"status": response.status_code, "duration_ms": duration_ms},
            )
            raise GraphError(f"Token request failed ({response.status_code}): {response.text}")
        self._token = response.json()["access_token"]
        self._emit(
            "graph.token.succeeded",
            "App token acquired",
            {"status": response.status_code, "duration_ms": duration_ms},
        )
        return self._token

    def _interactive_token(self) -> str:
        try:
            import msal
        except Exception as exc:  # noqa: BLE001
            raise GraphError(f"Interactive auth requires msal dependency: {exc}")

        requested_scopes = self.auth.interactive_scopes or [self.auth.graph_scope]
        scopes = list(dict.fromkeys(requested_scopes)) or ["User.Read"]
        if self.auth.graph_scope.endswith("/.default") and self.auth.graph_scope in scopes:
            scopes = [scope for scope in scopes if scope != self.auth.graph_scope]
            if not scopes:
                scopes = ["User.Read"]

        self._emit(
            "graph.token.interactive",
            "Starting interactive token acquisition",
            {"scopes": scopes, "authority": self._authority()},
        )
        app = msal.PublicClientApplication(
            client_id=self.auth.client_id,
            authority=self._authority(),
            token_cache=None,
        )
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(scopes=scopes, account=accounts[0])
            if result and "access_token" in result:
                self._token = result["access_token"]
                self._emit("graph.token.succeeded", "Interactive token loaded from cache", {"source": "cache"})
                return self._token

        result = app.acquire_token_interactive(scopes=scopes)
        if not result:
            self._emit("graph.token.failed", "Interactive auth returned no token", {"scopes": scopes})
            raise GraphError("Interactive auth was canceled or did not return a token.")
        if "access_token" not in result:
            error = result.get("error_description") or result.get("error") or "interactive login failed"
            self._emit("graph.token.failed", "Interactive auth returned error response", {"error": error})
            raise GraphError(error)
        self._token = result["access_token"]
        self._emit("graph.token.succeeded", "Interactive token acquired", {"source": "interactive"})
        return self._token

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        token = self.ensure_token()
        headers = kwargs.pop("headers", {})
        headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )
        attempt = 0
        while True:
            attempt += 1
            request_start = time.time()
            self._emit(
                "graph.request.started",
                "Graph request started",
                {
                    "method": method,
                    "url": url,
                    "attempt": attempt,
                    "params": self._params_overview(kwargs.get("params")),
                },
            )
            try:
                response = self.session.request(method, url, headers=headers, timeout=self.auth.timeout_seconds, **kwargs)
            except RequestException as exc:  # noqa: BLE001
                self._emit(
                    "graph.request.exception",
                    "Graph request raised exception",
                    {"method": method, "url": url, "error": str(exc), "attempt": attempt},
                )
                raise
            duration_ms = round((time.time() - request_start) * 1000, 2)
            self._emit(
                "graph.request.completed",
                "Graph request finished",
                {
                    "method": method,
                    "url": url,
                    "status": response.status_code,
                    "attempt": attempt,
                    "duration_ms": duration_ms,
                    "response_length": len(response.text),
                },
            )
            if response.status_code == 429 and attempt <= 3:
                retry_after = int(response.headers.get("Retry-After", "5"))
                LOG.warning("Graph rate limit. Retry in %s seconds.", retry_after)
                self._emit(
                    "graph.request.retry",
                    "Rate limited, retrying request",
                    {"method": method, "url": url, "retry_after_sec": retry_after, "attempt": attempt},
                )
                time.sleep(retry_after)
                continue
            if response.status_code >= 500 and attempt <= 2:
                LOG.warning("Graph server error (%s). Retrying (%s/2).", response.status_code, attempt)
                self._emit(
                    "graph.request.retry",
                    "Server error, retrying request",
                    {"method": method, "url": url, "status": response.status_code, "attempt": attempt},
                )
                time.sleep(1)
                continue
            return response

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None, full_url: bool = False) -> Dict[str, Any]:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        response = self._request("GET", url, params=params)
        if response.status_code >= 400:
            payload: dict[str, Any]
            error_code: str | None = None
            reason = response.text
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, dict):
                    error_code = error.get("code")
                    reason = str(error.get("message") or reason)
                elif isinstance(error, str):
                    reason = error
            self._emit(
                "graph.response.error",
                "Graph endpoint returned error response",
                {
                    "url": response.url,
                    "status": response.status_code,
                    "error_code": error_code,
                },
            )
            raise GraphError(reason, status=response.status_code, request=response.url, error_code=error_code)
        return response.json()

    def get_all(self, path: str, params: Optional[Dict[str, Any]] = None) -> list[Dict[str, Any]]:
        rows: list[Dict[str, Any]] = []
        page_url: Optional[str] = path if path.startswith("http") else f"{GRAPH_ROOT}{path}"
        current_params = params
        while page_url:
            payload = self.get_json(page_url, params=current_params, full_url=page_url.startswith("http"))
            if not isinstance(payload, dict):
                raise GraphError(f"Non-dict response from {page_url}", request=page_url)
            rows.extend(payload.get("value", []))
            page_url = payload.get("@odata.nextLink")
            current_params = None
        return rows
