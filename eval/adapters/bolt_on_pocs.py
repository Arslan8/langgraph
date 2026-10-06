"""Run E2 through released call-boundary bolt-on middleware.

The local authority doubles approve the shared, policy-conformant calls.  They do
not emulate a vendor policy engine: this experiment asks only whether the
released middleware's mediation point covers effects that happen after approval
inside the tool.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import ToolMessage

from slanggraph_eval.pocs import (
    load_replay_calls,
    replay_details,
    run_pocs,
    write_audit,
    write_results,
)


class _Approved:
    verified = True
    proof_id = "local-policy-conformant-call"
    reason = None


class _LocalAuthority:
    def verify_sync(self, **_request: Any) -> _Approved:
        return _Approved()


def _jsonable(value: Any) -> Any:
    """Keep the model-visible shape while naming injected runtime dependencies."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return {"injected_dependency": type(value).__name__}


def _make_wrapper(defense: str) -> tuple[Any, dict[str, Any]]:
    if defense == "eydii":
        from eydii_langgraph import EydiiVerifyMiddleware

        middleware = EydiiVerifyMiddleware(api_key="local-evaluation-key")
        middleware._client = _LocalAuthority()
        return middleware.wrap_tool_call, {
            "distribution": "langchain-eydii==0.1.1",
            "authority": "local approving double",
        }
    if defense == "forge":
        from forge_langgraph import ForgeVerifyMiddleware

        middleware = ForgeVerifyMiddleware(api_key="local-evaluation-key")
        middleware._client = _LocalAuthority()
        return middleware.wrap_tool_call, {
            "distribution": "langchain-forge==0.2.0",
            "transitive_pin": "veritera==0.4.0",
            "authority": "local approving double",
        }
    if defense == "nuggets":
        from langchain_nuggets import MiddlewareConfig, NuggetsAuthorityMiddleware

        config = MiddlewareConfig(
            api_url="http://127.0.0.1",
            agent_id="did:nuggets:oidc:slanggraph-eval",
            controller_id="local-controller",
            delegation_id="local-delegation",
            test_mode=True,
        )
        middleware = NuggetsAuthorityMiddleware(config)
        return middleware.wrap_tool_call, {
            "distribution": "langchain-nuggets==1.4.0",
            "authority": "released test_mode",
        }
    raise ValueError(f"unknown bolt-on: {defense}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defense", choices=["eydii", "forge", "nuggets"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--transcript", type=Path, required=True)
    args = parser.parse_args()
    wrapper, details = _make_wrapper(args.defense)

    def guard(tool: str, arguments: dict[str, Any]) -> None:
        called = False

        def handler(_request: Any) -> ToolMessage:
            nonlocal called
            called = True
            return ToolMessage(content="approved", tool_call_id=f"e2-{tool}")

        request = SimpleNamespace(
            tool_call={
                "name": tool,
                "args": _jsonable(arguments),
                "id": f"e2-{tool}",
            }
        )
        wrapper(request, handler)
        if not called:
            raise RuntimeError(f"{args.defense} denied policy-conformant call to {tool}")

    condition = f"bolt_on:{args.defense}"
    results = run_pocs(condition, guard, load_replay_calls(args.transcript))
    write_results(results, args.output)
    write_audit(
        results,
        args.audit_db,
        details={
            **replay_details(args.transcript),
            **details,
            "mediation": "released call-boundary wrapper",
            "policy_generation": False,
            "purpose": "coverage below an approved call, not vendor policy accuracy",
        },
    )
    print(
        json.dumps(
            {
                "condition": condition,
                "pocs": [{"tool": item.tool, "landed": item.landed} for item in results],
            }
        )
    )
    return 0 if all(item.landed for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
