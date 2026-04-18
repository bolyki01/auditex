from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from . import auth as auditex_auth


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SCRIPT = REPO_ROOT / "scripts" / "bootstrap-local-tools.sh"
SELECT_PYTHON_SCRIPT = REPO_ROOT / "scripts" / "select-python.sh"
DEFAULT_VENV_DIR = REPO_ROOT / ".venv"


def detect_package_manager() -> str | None:
    if shutil.which("brew"):
        return "brew"
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    return None


def _run_json_command(command: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return {
            "status": "blocked",
            "command": command,
            "error": "command_not_found",
        }

    return {
        "status": "supported" if completed.returncode == 0 else "blocked",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _command_version(command: list[str], *, parser: Callable[[str], str | None] | None = None) -> tuple[str | None, str | None]:
    result = _run_json_command(command)
    if result["status"] != "supported":
        error = (result.get("stderr") or result.get("stdout") or "").strip() or "version_check_failed"
        return None, error
    output = (result.get("stdout") or result.get("stderr") or "").strip()
    if not output:
        return None, "empty_version_output"
    if parser is not None:
        try:
            parsed = parser(output)
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if not parsed:
            return None, "empty_version_output"
        return parsed, None
    return output, None


def _tool_status(
    command_name: str,
    *,
    version_args: list[str] | None = None,
    version_parser: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    path = shutil.which(command_name)
    if not path:
        return {
            "name": command_name,
            "status": "blocked",
            "path": None,
            "version": None,
            "error": "command_not_found",
        }
    version = None
    error = None
    if version_args is not None:
        version, error = _command_version([path, *version_args], parser=version_parser)
    status = "supported" if version or version_args is None else "blocked"
    return {
        "name": command_name,
        "status": status,
        "path": path,
        "version": version,
        "error": error,
    }


def _selected_python() -> dict[str, Any]:
    if not SELECT_PYTHON_SCRIPT.exists():
        return {
            "status": "blocked",
            "error": "missing_select_python_script",
            "path": str(SELECT_PYTHON_SCRIPT),
        }

    result = _run_json_command(["bash", str(SELECT_PYTHON_SCRIPT)])
    stdout = (result.get("stdout") or "").strip()
    if result["status"] == "supported" and stdout:
        version, version_error = _command_version([stdout, "--version"])
        return {
            "status": "supported" if version else "blocked",
            "path": stdout,
            "version": version,
            "selector": str(SELECT_PYTHON_SCRIPT),
            "error": version_error,
        }
    return {
        "status": "blocked",
        "path": None,
        "selector": str(SELECT_PYTHON_SCRIPT),
        "error": (result.get("stderr") or result.get("stdout") or "").strip() or "no_supported_python",
    }


def _venv_status() -> dict[str, Any]:
    python_path = DEFAULT_VENV_DIR / "bin" / "python"
    return {
        "status": "supported" if python_path.exists() else "blocked",
        "path": str(DEFAULT_VENV_DIR),
        "python_path": str(python_path),
    }


def build_doctor_report() -> dict[str, Any]:
    auth_status = auditex_auth.get_auth_status()
    python_status = _selected_python()
    venv_status = _venv_status()
    tools = {
        "az": _tool_status(
            "az",
            version_args=["version", "--output", "json"],
            version_parser=lambda output: json.loads(output).get("azure-cli"),
        ),
        "node": _tool_status("node", version_args=["--version"]),
        "npm": _tool_status("npm", version_args=["--version"]),
        "m365": _tool_status(
            "m365",
            version_args=["version"],
            version_parser=lambda output: output.splitlines()[0].strip() if output.strip() else None,
        ),
        "pwsh": _tool_status("pwsh", version_args=["--version"]),
    }
    exchange = auth_status.get("exchange") or {}
    core_missing = [
        name
        for name, status in (
            ("python", python_status),
            ("venv", venv_status),
            ("az", tools["az"]),
        )
        if status["status"] != "supported"
    ]
    exchange_missing = [
        name
        for name, status in (
            ("node", tools["node"]),
            ("npm", tools["npm"]),
            ("m365", tools["m365"]),
            ("pwsh", tools["pwsh"]),
        )
        if status["status"] != "supported"
    ]
    if exchange.get("status") != "supported":
        exchange_missing.append("exchange_online_module")
    pwsh_missing = [name for name, status in (("pwsh", tools["pwsh"]),) if status["status"] != "supported"]
    return {
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "package_manager": detect_package_manager(),
        },
        "bootstrap": {
            "script": str(BOOTSTRAP_SCRIPT),
            "exists": BOOTSTRAP_SCRIPT.exists(),
        },
        "python": python_status,
        "venv": venv_status,
        "tools": tools,
        "auth": auth_status,
        "readiness": {
            "core_ready": not core_missing,
            "core_missing": core_missing,
            "exchange_ready": not exchange_missing,
            "exchange_missing": exchange_missing,
            "pwsh_ready": not pwsh_missing,
            "pwsh_missing": pwsh_missing,
        },
    }


def _format_tool_line(name: str, tool: dict[str, Any]) -> str:
    version = tool.get("version")
    path = tool.get("path")
    if tool.get("status") == "supported":
        parts = [name, "supported"]
        if version:
            parts.append(version)
        if path:
            parts.append(f"[{path}]")
        return ": ".join([parts[0], " ".join(parts[1:])])
    return f"{name}: blocked" + (f" ({tool.get('error')})" if tool.get("error") else "")


def _format_missing(label: str, missing: list[str]) -> str:
    if not missing:
        return f"{label}: yes"
    return f"{label}: no (need {', '.join(missing)})"


def format_doctor_report(report: dict[str, Any]) -> str:
    tools = report.get("tools") or {}
    auth = report.get("auth") or {}
    azure_cli = auth.get("azure_cli") or {}
    m365 = auth.get("m365") or {}
    exchange = auth.get("exchange") or {}
    readiness = report.get("readiness") or {}
    lines = [
        f"System: {report['system']['os']} {report['system']['machine']} ({report['system'].get('package_manager') or 'manual'})",
        _format_tool_line("Python", report["python"]),
        _format_tool_line("Venv", report["venv"]),
        _format_tool_line("Azure CLI", tools.get("az", {})),
        _format_tool_line("Node", tools.get("node", {})),
        _format_tool_line("npm", tools.get("npm", {})),
        _format_tool_line("m365", tools.get("m365", {})),
        _format_tool_line("pwsh", tools.get("pwsh", {})),
        f"Azure auth: {azure_cli.get('status')}" + (f" [{azure_cli.get('user_name')}]" if azure_cli.get("user_name") else ""),
        f"m365 auth: {m365.get('status')}" + (f" [{m365.get('active_connection')}]" if m365.get("active_connection") else ""),
        "Exchange module: "
        + ("supported" if exchange.get("status") == "supported" else "blocked")
        + (f" [{exchange.get('module_version')}]" if exchange.get("module_version") else ""),
        _format_missing("Core ready", readiness.get("core_missing") or []),
        _format_missing("Exchange ready", readiness.get("exchange_missing") or []),
        _format_missing("Pwsh ready", readiness.get("pwsh_missing") or []),
    ]
    return "\n".join(lines)


def run_setup(*, with_exchange: bool = False, with_pwsh: bool = False, with_mcp: bool = False) -> int:
    if not BOOTSTRAP_SCRIPT.exists():
        raise RuntimeError(f"missing bootstrap script: {BOOTSTRAP_SCRIPT}")
    command = ["bash", str(BOOTSTRAP_SCRIPT)]
    if with_exchange:
        command.append("--exchange")
    if with_pwsh:
        command.append("--pwsh")
    if with_mcp:
        command.append("--mcp")
    return subprocess.run(command, check=False).returncode


def print_doctor_report(*, json_output: bool = False) -> int:
    report = build_doctor_report()
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(format_doctor_report(report))
    return 0
