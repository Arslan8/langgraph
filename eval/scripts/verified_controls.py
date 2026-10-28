"""Production verifier and authorization negative controls, separate from timing."""

import json
import tempfile
import uuid
from pathlib import Path

from langgraph.prebuilt.security import cedar_security
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied

from slanggraph_eval.isolation.run import invoke_host
from slanggraph_eval.isolation.verified import MANIFEST, verified_read

ROOT = Path(__file__).resolve().parents[1] / "reports/alternatives-v2"
rows = []
for repetition in range(3):
    with tempfile.TemporaryDirectory(prefix="verified-controls-") as temporary:
        root = Path(temporary)
        allowed = root / "allowed"
        hidden = root / "hidden"
        marker = root / "executed"
        token = uuid.uuid4().hex
        allowed.write_text(token)
        hidden.write_text(uuid.uuid4().hex)
        policy = (
            'permit(principal, action == slangGraph::Action::"call", resource);\n'
            'permit(principal, action == slangGraph::Action::"fs::read", resource) '
            "when { resource.selector == " + json.dumps(str(allowed)) + " };"
        )
        security = cedar_security(verified_read, manifest=MANIFEST, policy=policy)
        value, receipt = invoke_host(security.host_executor, {"path": str(allowed)})
        assert value == token
        rows.append(
            dict(case="permitted_read", repetition=repetition, passed=True, receipt=receipt)
        )
        try:
            invoke_host(security.host_executor, {"path": str(hidden)})
        except HostExecutionDenied as error:
            rows.append(
                dict(
                    case="ungranted_path_argument",
                    repetition=repetition,
                    passed=True,
                    error=str(error),
                )
            )
        else:
            raise AssertionError("ungranted path accepted")
        original = verified_read.func
        try:
            verified_read.func = lambda path, marker=marker: marker.write_text(
                "unexpected execution"
            )
            try:
                invoke_host(security.host_executor, {"path": str(allowed)})
            except HostExecutionDenied as error:
                assert not marker.exists()
                rows.append(
                    dict(
                        case="changed_callable_binding",
                        repetition=repetition,
                        passed=True,
                        error=str(error),
                    )
                )
            else:
                raise AssertionError("changed binding executed")
        finally:
            verified_read.func = original
        try:
            cedar_security(verified_read, manifest="runs inprocess", policy=policy)
        except SecurityConfigurationError as error:
            rows.append(
                dict(
                    case="missing_read_manifest",
                    repetition=repetition,
                    passed=True,
                    error=str(error),
                )
            )
        else:
            raise AssertionError("inconsistent manifest admitted")
(ROOT / "verified-security.json").write_text(json.dumps(rows, indent=2) + "\n")
print("12/12 production verified-mode controls passed.")
