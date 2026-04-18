from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.utils import load_env_file, parse_csv_list


LOCAL_AUTH_ENV_VAR = "AUDITEX_LOCAL_AUTH_ENV"
AUTH_CONTEXTS_PATH_ENV_VAR = "AUDITEX_AUTH_CONTEXTS_PATH"


def default_local_auth_env_path() -> Path:
    configured = os.environ.get(LOCAL_AUTH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    cwd_path = Path.cwd() / ".secrets" / "m365-auth.env"
    if cwd_path.exists():
        return cwd_path
    return Path(__file__).resolve().parents[2] / ".secrets" / "m365-auth.env"


def default_auth_contexts_path() -> Path:
    configured = os.environ.get(AUTH_CONTEXTS_PATH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    cwd_path = Path.cwd() / ".secrets" / "auditex-auth-contexts.json"
    if cwd_path.exists():
        return cwd_path
    return Path(__file__).resolve().parents[2] / ".secrets" / "auditex-auth-contexts.json"


def _load_local_auth_env() -> Path:
    path = default_local_auth_env_path()
    load_env_file(path)
    return path


def _masked_local_auth_values(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {"path": str(path), "present": path.exists()}
    if not path.exists():
        return values
    keys = (
        "M365_CLI_APP_ID",
        "M365_CLI_CLIENT_ID",
        "AUDITEX_M365_CONNECTION_NAME",
        "AUDITEX_TENANT_ID",
    )
    values["values"] = {key: os.environ.get(key) for key in keys if os.environ.get(key)}
    return values


def _json_command(command: list[str]) -> dict[str, Any]:
    exe = shutil.which(command[0])
    if exe is None:
        return {
            "status": "blocked",
            "error_class": "command_not_found",
            "error": f"{command[0]} not installed",
            "command": command,
        }
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    payload: Any = None
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = None
    return {
        "status": "supported" if completed.returncode == 0 else "blocked",
        "returncode": completed.returncode,
        "command": command,
        "payload": payload,
        "stdout": stdout,
        "stderr": stderr,
    }


def _pwsh_exchange_module_status() -> dict[str, Any]:
    pwsh_exe = shutil.which("pwsh")
    if pwsh_exe is None:
        return {
            "status": "blocked",
            "error_class": "command_not_found",
            "error": "pwsh not installed",
        }
    completed = subprocess.run(
        [
            pwsh_exe,
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-Module -ListAvailable ExchangeOnlineManagement | "
            "Select-Object -First 1 Name,Version | ConvertTo-Json -Compress",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode == 0 and stdout and stdout != "null":
        payload: dict[str, Any] | None = None
        try:
            decoded = json.loads(stdout)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None
        return {
            "status": "supported",
            "pwsh_path": pwsh_exe,
            "module_name": (payload or {}).get("Name") or "ExchangeOnlineManagement",
            "module_version": (payload or {}).get("Version"),
        }
    return {
        "status": "blocked",
        "pwsh_path": pwsh_exe,
        "error_class": "module_not_found",
        "error": stderr or stdout or f"return_code:{completed.returncode}",
    }


def ensure_exchange_online_module() -> int:
    status = _pwsh_exchange_module_status()
    if status.get("status") == "supported":
        return 0
    pwsh_exe = status.get("pwsh_path")
    if not pwsh_exe:
        return 2
    command = [
        str(pwsh_exe),
        "-NoLogo",
        "-NoProfile",
        "-Command",
        "Set-PSRepository PSGallery -InstallationPolicy Trusted; "
        "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber",
    ]
    return subprocess.run(command, check=False).returncode


def _load_json(path: Path, *, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _auth_context_store() -> dict[str, Any]:
    store = _load_json(default_auth_contexts_path(), default={"active_context": None, "contexts": {}})
    if not isinstance(store, dict):
        return {"active_context": None, "contexts": {}}
    if not isinstance(store.get("contexts"), dict):
        store["contexts"] = {}
    return store


def _save_auth_context_store(payload: dict[str, Any]) -> None:
    _save_json(default_auth_contexts_path(), payload)


def _b64url_json(segment: str) -> dict[str, Any]:
    if not segment:
        return {}
    padding = "=" * ((4 - len(segment) % 4) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def _iso_from_epoch(value: Any) -> str | None:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inspect_token_claims(token: str) -> dict[str, Any]:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("token is not a JWT")
    payload = _b64url_json(parts[1])
    delegated_scopes = sorted(parse_csv_list(str(payload.get("scp", "")).replace(" ", ",")))
    app_roles = sorted(str(item) for item in payload.get("roles", []) if isinstance(item, str))
    return {
        "tenant_id": payload.get("tid"),
        "audience": payload.get("aud"),
        "app_id": payload.get("appid") or payload.get("azp"),
        "subject": payload.get("sub"),
        "user_principal_name": payload.get("upn") or payload.get("preferred_username"),
        "delegated_scopes": delegated_scopes,
        "app_roles": app_roles,
        "issued_at_utc": _iso_from_epoch(payload.get("iat")),
        "not_before_utc": _iso_from_epoch(payload.get("nbf")),
        "expires_at_utc": _iso_from_epoch(payload.get("exp")),
        "raw_claims": payload,
    }


def _redacted_token_preview(token: str) -> str:
    token = token.strip()
    if len(token) <= 12:
        return "***redacted***"
    return f"{token[:8]}...{token[-4:]}"


def import_token_context(
    *,
    name: str,
    token: str,
    tenant_id: str | None = None,
    make_active: bool = True,
) -> dict[str, Any]:
    inspected = inspect_token_claims(token)
    effective_tenant_id = tenant_id or inspected.get("tenant_id")
    store = _auth_context_store()
    store["contexts"][name] = {
        "name": name,
        "auth_type": "imported_token",
        "tenant_id": effective_tenant_id,
        "token": token,
        "token_preview": _redacted_token_preview(token),
        "token_claims": inspected,
    }
    if make_active:
        store["active_context"] = name
    _save_auth_context_store(store)
    return {
        "name": name,
        "auth_type": "imported_token",
        "tenant_id": effective_tenant_id,
        "token_preview": _redacted_token_preview(token),
        "token_claims": {
            "audience": inspected.get("audience"),
            "delegated_scopes": inspected.get("delegated_scopes", []),
            "app_roles": inspected.get("app_roles", []),
            "expires_at_utc": inspected.get("expires_at_utc"),
        },
    }


def list_auth_contexts() -> dict[str, Any]:
    store = _auth_context_store()
    contexts: list[dict[str, Any]] = []
    active = store.get("active_context")
    for name, item in sorted(store.get("contexts", {}).items()):
        if not isinstance(item, dict):
            continue
        contexts.append(
            {
                "name": name,
                "active": name == active,
                "auth_type": item.get("auth_type"),
                "tenant_id": item.get("tenant_id"),
                "token_preview": item.get("token_preview"),
                "user_principal_name": ((item.get("token_claims") or {}).get("user_principal_name")),
                "audience": ((item.get("token_claims") or {}).get("audience")),
            }
        )
    return {"active_context": active, "contexts": contexts}


def resolve_auth_context(name: str | None = None) -> dict[str, Any]:
    store = _auth_context_store()
    selected_name = name or store.get("active_context")
    if not selected_name:
        raise RuntimeError("no saved auth context")
    context = store.get("contexts", {}).get(selected_name)
    if not isinstance(context, dict):
        raise RuntimeError(f"auth context '{selected_name}' not found")
    return context


def _load_permission_hints(path: Path) -> dict[str, dict[str, Any]]:
    payload = _load_json(path, default={})
    hints = payload.get("collector_permissions") if isinstance(payload, dict) else {}
    if not isinstance(hints, dict):
        return {}
    return {str(key): dict(value) if isinstance(value, dict) else {} for key, value in hints.items()}


def _available_permissions(token_claims: dict[str, Any]) -> set[str]:
    scopes = token_claims.get("delegated_scopes") or []
    roles = token_claims.get("app_roles") or []
    return {str(item) for item in scopes if item} | {str(item) for item in roles if item}


def _has_global_reader_like_role(context: dict[str, Any]) -> bool:
    roles = context.get("delegated_roles") or []
    return any(str(item).lower() == "global reader" for item in roles)


def collector_capability_matrix(
    *,
    auth_context: dict[str, Any],
    collectors: list[str],
    auditor_profile: str = "auto",
    config_path: str = "configs/collector-definitions.json",
    permission_hints_path: str = "configs/collector-permissions.json",
) -> list[dict[str, Any]]:
    config = CollectorConfig.from_path(Path(config_path))
    permission_hints = _load_permission_hints(Path(permission_hints_path))
    profile = get_profile(auditor_profile)
    token_claims = auth_context.get("token_claims") or {}
    available = _available_permissions(token_claims)
    has_global_reader = _has_global_reader_like_role(auth_context)
    rows: list[dict[str, Any]] = []
    for collector_name in collectors:
        definition = config.collectors.get(collector_name)
        hints = permission_hints.get(collector_name, {})
        required = list(definition.required_permissions) if definition else list(hints.get("graph_scopes") or [])
        missing = [item for item in required if item not in available]
        status = "supported"
        reason = "required_permissions_present"
        if missing:
            status = "blocked_by_scope"
            reason = "missing_required_permissions"
        if collector_name in {"purview", "ediscovery"} and has_global_reader:
            status = "blocked_by_role"
            reason = "global_reader_limit"
        elif collector_name == "reports_usage" and has_global_reader and "Reports.Read.All" not in available:
            status = "partial"
            reason = "global_reader_tenant_level_reports_only"
        rows.append(
            {
                "collector": collector_name,
                "status": status,
                "reason": reason,
                "required_permissions": required,
                "missing_permissions": missing,
                "observed_permissions": sorted(available),
                "minimum_role_hints": list(hints.get("minimum_role_hints") or profile.delegated_role_hints),
                "notes": hints.get("notes") or profile.notes,
            }
        )
    return rows


def capability_for_context(
    *,
    name: str | None = None,
    collectors: list[str],
    auditor_profile: str = "auto",
    config_path: str = "configs/collector-definitions.json",
    permission_hints_path: str = "configs/collector-permissions.json",
) -> dict[str, Any]:
    context = resolve_auth_context(name)
    return {
        "auth_context": {
            "name": context.get("name"),
            "auth_type": context.get("auth_type"),
            "tenant_id": context.get("tenant_id"),
            "token_claims": {
                "audience": ((context.get("token_claims") or {}).get("audience")),
                "delegated_scopes": ((context.get("token_claims") or {}).get("delegated_scopes")) or [],
                "app_roles": ((context.get("token_claims") or {}).get("app_roles")) or [],
                "expires_at_utc": ((context.get("token_claims") or {}).get("expires_at_utc")),
            },
        },
        "capabilities": collector_capability_matrix(
            auth_context=context,
            collectors=collectors,
            auditor_profile=auditor_profile,
            config_path=config_path,
            permission_hints_path=permission_hints_path,
        ),
    }


def get_auth_status() -> dict[str, Any]:
    path = _load_local_auth_env()
    azure = _json_command(["az", "account", "show", "--output", "json"])
    m365 = _json_command(["m365", "status", "--output", "json"])
    connections = _json_command(["m365", "connection", "list", "--output", "json"])
    exchange = _pwsh_exchange_module_status()

    result: dict[str, Any] = {
        "local_auth": _masked_local_auth_values(path),
        "azure_cli": {
            "status": azure["status"],
        },
        "m365": {
            "status": m365["status"],
        },
        "exchange": exchange,
        "auth_contexts": list_auth_contexts(),
    }
    if azure.get("payload"):
        payload = azure["payload"]
        result["azure_cli"]["tenant_id"] = payload.get("tenantId") or payload.get("tenant_id")
        user = payload.get("user") or {}
        if isinstance(user, dict):
            result["azure_cli"]["user_name"] = user.get("name")
            result["azure_cli"]["user_type"] = user.get("type")
    else:
        result["azure_cli"]["error"] = (azure.get("stderr") or azure.get("stdout") or "").strip()

    if m365.get("payload"):
        payload = m365["payload"]
        if isinstance(payload, dict):
            result["m365"].update(
                {
                    "active_connection": payload.get("connectionName"),
                    "connected_as": payload.get("connectedAs"),
                    "auth_type": payload.get("authType"),
                    "app_id": payload.get("appId"),
                    "tenant_id": payload.get("appTenant"),
                    "cloud_type": payload.get("cloudType"),
                    "authenticated": bool(payload.get("connectionName") or payload.get("connectedAs")),
                }
            )
    else:
        result["m365"]["error"] = (m365.get("stderr") or m365.get("stdout") or "").strip()
        result["m365"]["authenticated"] = False

    if connections.get("payload") is not None:
        result["m365"]["saved_connections"] = connections.get("payload")
    elif connections.get("status") == "blocked":
        result["m365"]["saved_connections_error"] = (connections.get("stderr") or connections.get("stdout") or "").strip()

    return result


def list_connections() -> dict[str, Any]:
    _load_local_auth_env()
    response = _json_command(["m365", "connection", "list", "--output", "json"])
    if response["status"] == "blocked":
        raise RuntimeError((response.get("stderr") or response.get("stdout") or "unable to list connections").strip())
    return {"connections": response.get("payload") or []}


def use_connection(name: str) -> dict[str, Any]:
    _load_local_auth_env()
    response = _json_command(["m365", "connection", "use", "--name", name, "--output", "json"])
    if response["status"] == "blocked":
        raise RuntimeError((response.get("stderr") or response.get("stdout") or "unable to switch connection").strip())
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else {"connectionName": name}


def export_env() -> dict[str, Any]:
    path = _load_local_auth_env()
    return _masked_local_auth_values(path)


def login_connection(
    *,
    mode: str,
    tenant_id: str | None = None,
    connection_name: str | None = None,
    auth_type: str | None = None,
    app_id: str | None = None,
    client_secret: str | None = None,
) -> int:
    _load_local_auth_env()
    if mode not in {"delegated", "app"}:
        raise ValueError(f"unsupported auth mode: {mode}")

    if mode == "delegated":
        command = [
            "m365",
            "login",
            "--authType",
            auth_type or "deviceCode",
        ]
        effective_app_id = app_id or os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
        if effective_app_id:
            command.extend(["--appId", effective_app_id])
        if tenant_id:
            command.extend(["--tenant", tenant_id])
        if connection_name:
            command.extend(["--connectionName", connection_name])
        return subprocess.run(command, check=False).returncode

    effective_app_id = app_id or os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
    if not effective_app_id or not client_secret:
        raise ValueError("app auth requires app_id and client_secret")
    command = [
        "m365",
        "login",
        "--authType",
        "secret",
        "--appId",
        effective_app_id,
        "--secret",
        client_secret,
    ]
    if tenant_id:
        command.extend(["--tenant", tenant_id])
    if connection_name:
        command.extend(["--connectionName", connection_name])
    return subprocess.run(command, check=False).returncode
