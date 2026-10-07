"""Install `ResourceBoundary` and show it reaching actual worker authority.

The policy bounds a fixture project:

| Resource | Maximum authority |
| --- | --- |
| `src/**` | read |
| `artifacts/**` | read, write, create, delete, truncate |
| `credentials/**` | none |
| `project.toml` | read |

Two unchanged tools request read+write on a source file. The example first
prints the policy result for both, then, when bubblewrap isolation is
available, runs them in Linux workers where the kernel blocks the write.
"""

import hashlib
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock

from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool
from resource_boundary_tools import count_lines, summarize_source

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceAllowance,
    ResourceArg,
    ResourceBoundary,
    ResourceBoundaryPolicy,
    SecurityConfig,
    SecurityStack,
    Tool,
    ToolCall,
    ToolDac,
    TypedPolicyBackend,
    compile_grant,
    effects,
    parse_profiles,
    resource_path,
    with_principal,
)

_EXAMPLES = Path(__file__).resolve().parent
_ARTIFACT = _EXAMPLES / "resource_boundary_tools.py"
_TOOLS = {"summarize_source": "path", "count_lines": "file"}


def build_policy(project: Path) -> ResourceBoundaryPolicy:
    """Return the operator policy; selectors use the `.slp` path grammar."""
    return ResourceBoundaryPolicy(
        policy_id="project-boundary",
        version="2026-10-07",
        scope=resource_path(f"{project}/**"),
        allow=(
            ResourceAllowance(resource_path(f"{project}/src/**"), {"read"}),
            ResourceAllowance(
                resource_path(f"{project}/artifacts/**"),
                {"read", "write", "create", "delete", "truncate"},
            ),
            ResourceAllowance(resource_path(f"{project}/project.toml"), {"read"}),
        ),
        forbid=(resource_path(f"{project}/credentials/**"),),
    )


def build_profiles(project: Path) -> str:
    """Author DAC: each tool optionally wants read+write on its argument."""
    tools = "".join(
        f"""
tool {name} {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read+write+truncate ${{{argument}}} want
}}"""
        for name, argument in _TOOLS.items()
    )
    return f"""{tools}
principal alice {{
  roles analyst
  fs {project}/**
}}
"""


def adapt(function) -> StructuredTool:
    """Wrap an unchanged function; attach metadata to the new tool only."""
    adapted = StructuredTool.from_function(function)
    argument = _TOOLS[function.__name__]
    return effects(
        Effect.READ, resources=[ResourceArg(argument, "path", "realpath")]
    )(adapted)


def policy_preview(
    profiles, boundary: ResourceBoundary, principal: Principal, source: Path
) -> None:
    """Show the semantic result: identical effective authority for both tools."""
    stack = SecurityStack([boundary])
    results = {}
    try:
        for name, argument in _TOOLS.items():
            evaluation = profiles.evaluate(name, "alice", {argument: str(source)})
            compiled = compile_grant(
                evaluation,
                principal_id="alice",
                session_id=principal.session_id,
                artifact_digest="preview",
                call_id=f"preview-{name}",
                normalized_intent_digest="preview",
                policy_digest="pre-mac",
            )
            tool = Tool(
                name,
                ToolDac("analyst", {"analyst": "x"}),
                frozenset({Effect.READ}),
                (ResourceArg(argument, "path", "realpath"),),
            )
            normalized = {argument: str(source)}
            call = ToolCall(tool, normalized, normalized, f"preview-{name}", 0)
            decision = stack.permission(principal, call)
            filtered = TypedPolicyBackend().filter(
                compiled.grant, compiled.ledger, decision.constraints
            )
            results[name] = sorted(
                (rule.operation, str(Path(rule.selector).relative_to(source.parents[1])))
                for rule in filtered.grant.rules
                if rule.domain.value == "filesystem"
            )
            print(f"policy result for {name}: {results[name]}")
    finally:
        stack.close()
    same = results["summarize_source"] == results["count_lines"]
    assert same
    print("effective authority: identical for both tools")


def run_in_workers(profiles, security_modules, principal, source: Path) -> None:
    """Run both tools through `ToolNode` into fresh Linux workers."""
    digest = hashlib.sha256(_ARTIFACT.read_bytes()).hexdigest()
    try:
        executor = LinuxSandboxExecutor(
            profiles,
            {
                name: LinuxToolSpec(f"resource_boundary_tools:{name}", _ARTIFACT, digest)
                for name in _TOOLS
            },
            runtime_roots=(_EXAMPLES,),
        )
    except RuntimeError as exc:
        print(f"linux enforcement: unavailable on this host ({exc})")
        return
    security = SecurityConfig(
        modules=security_modules,
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )
    node = ToolNode(
        [adapt(summarize_source), adapt(count_lines)], security=security
    )
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)
    for index, (name, argument) in enumerate(_TOOLS.items()):
        message = AIMessage(
            content="",
            tool_calls=[
                {"name": name, "args": {argument: str(source)}, "id": f"call-{index}"}
            ],
        )
        result = node.invoke({"messages": [message]}, config=config)["messages"][0]
        print(f"worker result for {name}: {result.content}")
    assert source.read_text() == "print('hello')\n"
    plans = {
        evidence.native_plan_digest
        for receipt in executor.activation_receipts()
        for evidence in receipt.evidence
    }
    print(f"activated workers: {len(executor.activation_receipts())}, "
          f"distinct mount plans: {len(plans)}")


def main() -> None:
    # The worker's private /tmp is runtime-baseline authority, so a controlled
    # scope under host /tmp would deny every call. Use /var/tmp instead.
    workspace = Path(tempfile.mkdtemp(prefix="resource-boundary-", dir="/var/tmp"))
    try:
        project = workspace.resolve() / "project"
        for directory in ("src", "artifacts", "credentials"):
            (project / directory).mkdir(parents=True)
        source = project / "src" / "app.py"
        source.write_text("print('hello')\n")
        (project / "credentials" / "token.txt").write_text("fixture only\n")
        (project / "project.toml").write_text("name = 'demo'\n")

        profiles = parse_profiles(build_profiles(project), source="example.slp")
        boundary = ResourceBoundary(build_policy(project))
        principal = Principal("alice", frozenset({"analyst"}), frozenset(), "demo")
        policy_preview(profiles, boundary, principal, source)
        run_in_workers(profiles, [boundary], principal, source)
    finally:
        shutil.rmtree(workspace)


if __name__ == "__main__":
    main()
