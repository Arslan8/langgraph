"""Evaluation-adapter lifecycle tests; key changes always recreate the container."""

import argparse
import hashlib
import json
import platform
import tempfile
import time
from pathlib import Path

from slanggraph_eval.isolation.alternatives import container_session, execute

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
FIRST = """from pathlib import Path
Path('/tmp/prior-private').write_text('A-credential')
result={'allowed':open(p['allowed']).read(),'broad':open(p['private']).read()}
"""
SECOND = """result={'allowed':open(p['allowed']).read()}
for label,path in [('old_authority',p['private']),('residual','/tmp/prior-private')]:
    try:
        result[label]=open(path).read()
    except OSError as error:
        result[label]={'denied':type(error).__name__}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "plan.json").write_text(
        json.dumps(
            dict(
                repetitions=20,
                image=IMAGE,
                implementation=(
                    "evaluation-adapter keyed harness; not integrated production contract"
                ),
                reuse_key=[
                    "principal",
                    "policy_digest",
                    "read_selectors",
                    "write_selectors",
                    "image",
                    "seccomp_profile",
                ],
                cleanup="docker rm -f on any key change; no cross-grant reuse",
                costs=(
                    "observed recreation under concurrent campaign work; not"
                    " publication latency cohort"
                ),
            ),
            indent=2,
        )
    )
    with (args.output / "trials.jsonl").open("w") as stream:
        for repeat in range(20):
            for case in ["broad_to_narrow", "principal_A_to_B", "operator_forbid_change"]:
                with tempfile.TemporaryDirectory(prefix="slg-container-lifecycle-") as tmp:
                    allowed = Path(tmp) / "allowed"
                    private = Path(tmp) / "private"
                    allowed.write_text("authorized")
                    private.write_text("A-private")
                    parameters = dict(allowed=str(allowed), private=str(private))
                    lifecycle = []
                    start = time.perf_counter()
                    keys = [
                        dict(
                            principal="A",
                            policy="v1",
                            reads=[str(allowed), str(private)],
                            image=IMAGE,
                            seccomp="minimal",
                        ),
                        dict(
                            principal="B" if case == "principal_A_to_B" else "A",
                            policy="v2" if case == "operator_forbid_change" else "v1",
                            reads=[str(allowed)],
                            image=IMAGE,
                            seccomp="minimal",
                        ),
                    ]
                    with container_session(keys[0]["reads"], [], IMAGE, lifecycle) as container:
                        first = execute(
                            "container",
                            FIRST,
                            parameters,
                            keys[0]["reads"],
                            [],
                            IMAGE,
                            container=container,
                        )
                    with container_session(keys[1]["reads"], [], IMAGE, lifecycle) as container:
                        second = execute(
                            "container",
                            SECOND,
                            parameters,
                            keys[1]["reads"],
                            [],
                            IMAGE,
                            container=container,
                        )
                    value = second.get("value", {})
                    passed = (
                        first.get("value") == {"allowed": "authorized", "broad": "A-private"}
                        and value.get("allowed") == "authorized"
                        and isinstance(value.get("old_authority"), dict)
                        and isinstance(value.get("residual"), dict)
                        and lifecycle[0]["container_id"] != lifecycle[1]["container_id"]
                    )
                    row = dict(
                        case_id=case,
                        repeat=repeat,
                        session=repeat,
                        mode="evaluation_container_recreation",
                        concrete_executor="alternatives.container_session/execute",
                        host=platform.node(),
                        source_revision=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        grant_input=keys,
                        decision="recreate",
                        production_activation="not-applicable",
                        telemetry=[first, second],
                        lifecycle=lifecycle,
                        legitimate_result=value.get("allowed") == "authorized",
                        observed_effect=value.get("old_authority") == "A-private"
                        or value.get("residual") == "A-credential",
                        passed=passed,
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
            print(f"lifecycle repeat {repeat} complete", flush=True)


if __name__ == "__main__":
    main()
