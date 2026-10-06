"""Verify configured models through Ollama's OpenAI-compatible tool API."""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

from .audit import AuditWriter


def probe_models(config_path: Path, audit_db: Path) -> tuple[dict[str, Any], ...]:
    """Require one deterministic tool call from each configured local model."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    endpoint = config["endpoint"].rstrip("/") + "/chat/completions"
    results: list[dict[str, Any]] = []
    for model in config["models"]:
        request_body = {
            "model": model["tag"],
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Call record_canary with value SETUP_CANARY. Do not answer in prose."
                    ),
                }
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "record_canary",
                        "description": "Record a setup canary.",
                        "parameters": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                    },
                }
            ],
            "tool_choice": "required",
            "temperature": config["temperature"],
            "seed": config["seed"],
            "options": {"num_ctx": model["num_ctx"]},
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(request_body).encode(),
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=300) as response:
            payload = json.load(response)
        calls = payload["choices"][0]["message"].get("tool_calls", [])
        passed = any(
            call.get("function", {}).get("name") == "record_canary"
            and json.loads(call["function"]["arguments"]).get("value") == "SETUP_CANARY"
            for call in calls
        )
        result = {
            "tag": model["tag"],
            "local_id": model["local_id"],
            "model_digest": model["model_digest"],
            "num_ctx": model["num_ctx"],
            "temperature": config["temperature"],
            "seed": config["seed"],
            "tool_call_observed": passed,
            "usage": payload.get("usage"),
        }
        results.append(result)
        with AuditWriter(
            audit_db,
            experiment="SETUP",
            condition="ollama_openai_compatible_probe",
            metadata={
                "hardware": "eval/HARDWARE.md",
                "model": model,
                "temperature": config["temperature"],
                "seed": config["seed"],
                "num_ctx": model["num_ctx"],
            },
        ) as audit:
            audit.append("model_probe", result)
    return tuple(results)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    args = parser.parse_args()
    results = probe_models(args.config, args.audit_db)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(result["tool_call_observed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
