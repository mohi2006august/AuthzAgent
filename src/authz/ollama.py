"""Minimal client for a local Ollama server (standard library only).

Used for the free, local runs: the grounded model parser and the reference agent can run on an
open-weight model on your own machine instead of the Anthropic API. Nothing leaves localhost.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_HOST = "http://localhost:11434"


class OllamaError(RuntimeError):
    pass


def post(host: str, path: str, body: dict[str, Any], timeout: float = 600.0) -> dict[str, Any]:
    request = urllib.request.Request(host.rstrip("/") + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OllamaError(f"cannot reach Ollama at {host}: {exc}") from exc


def installed_models(host: str = DEFAULT_HOST, timeout: float = 5.0) -> list[str]:
    request = urllib.request.Request(host.rstrip("/") + "/api/tags")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return [m["name"] for m in json.loads(response.read()).get("models", [])]
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OllamaError(f"cannot reach Ollama at {host}: {exc}") from exc


def has_model(name: str, models: list[str]) -> bool:
    """``llama3.2`` matches ``llama3.2:latest``; an explicit tag must match exactly."""
    return name in models or (":" not in name and f"{name}:latest" in models)
