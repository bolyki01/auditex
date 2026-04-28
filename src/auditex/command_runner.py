from __future__ import annotations

import subprocess
from typing import Any


SENSITIVE_ARGS = {
    "--access-token",
    "--client-secret",
    "--token",
    "--command-override",
    "--adapter-override",
}


def _sensitive_values(command: list[str]) -> set[str]:
    values: set[str] = set()
    skip_next = False
    for item in command:
        if skip_next:
            values.add(item)
            skip_next = False
            continue
        if item in SENSITIVE_ARGS:
            skip_next = True
            continue
        for flag in SENSITIVE_ARGS:
            prefix = f"{flag}="
            if item.startswith(prefix):
                values.add(item[len(prefix) :])
    return {value for value in values if value}


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for item in command:
        if skip_next:
            redacted.append("***redacted***")
            skip_next = False
            continue
        if item in SENSITIVE_ARGS:
            redacted.append(item)
            skip_next = True
            continue
        replaced = item
        for flag in SENSITIVE_ARGS:
            prefix = f"{flag}="
            if item.startswith(prefix):
                replaced = f"{flag}=***redacted***"
                break
        redacted.append(replaced)
    if skip_next:
        redacted.append("***redacted***")
    return redacted


def _redact_text(value: str, sensitive_values: set[str]) -> str:
    redacted = value
    for sensitive in sorted(sensitive_values, key=len, reverse=True):
        redacted = redacted.replace(sensitive, "***redacted***")
    return redacted


def run_cli_command(command: list[str], cwd: str | None = None, *, timeout_seconds: int = 900) -> dict[str, Any]:
    sensitive_values = _sensitive_values(command)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "command": redact_command(command),
            "returncode": None,
            "stdout": _redact_text(stdout, sensitive_values),
            "stderr": _redact_text(stderr, sensitive_values),
            "error_class": "timeout",
            "error": f"command timed out after {timeout_seconds}s",
        }
    return {
        "command": redact_command(command),
        "returncode": completed.returncode,
        "stdout": _redact_text(completed.stdout, sensitive_values),
        "stderr": _redact_text(completed.stderr, sensitive_values),
    }
