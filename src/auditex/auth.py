from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from azure_tenant_audit.utils import load_env_file


LOCAL_AUTH_ENV_VAR = "AUDITEX_LOCAL_AUTH_ENV"


def default_local_auth_env_path() -> Path:
    configured = os.environ.get(LOCAL_AUTH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    cwd_path = Path.cwd() / ".secrets" / "m365-auth.env"
    if cwd_path.exists():
        return cwd_path
    return Path(__file__).resolve().parents[2] / ".secrets" / "m365-auth.env"


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


def get_auth_status() -> dict[str, Any]:
    path = _load_local_auth_env()
    azure = _json_command(["az", "account", "show", "--output", "json"])
    m365 = _json_command(["m365", "status", "--output", "json"])
    connections = _json_command(["m365", "connection", "list", "--output", "json"])

    result: dict[str, Any] = {
        "local_auth": _masked_local_auth_values(path),
        "azure_cli": {
            "status": azure["status"],
        },
        "m365": {
            "status": m365["status"],
        },
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
                }
            )
    else:
        result["m365"]["error"] = (m365.get("stderr") or m365.get("stdout") or "").strip()

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
