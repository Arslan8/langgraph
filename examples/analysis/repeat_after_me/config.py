"""Demo composition root; fixed policy, classifier and storage are replaceable."""

from langgraph.prebuilt.analysis import AccessContext, AnalysisClient, AnalysisConfig, AnalysisRuntime, BUILTIN_EVENTS, Coverage, NotificationHub, Registry
from langgraph.prebuilt.analysis.provenance.sqlite import SqliteProvenanceStore
from langgraph.prebuilt.analysis_plugins.repeat_after_me import RepeatAfterMeAnalyzer, ScriptedClassifier
from langgraph.prebuilt.security import Principal, SecurityConfig
from langgraph.prebuilt.security.modules.repeat_after_me import RepeatAfterMePolicy

POLICY_JSON = '{"version":1,"profile":"repeat_after_me","deny":["example.ram.suspected","example.ram.unknown"],"tools":["record_demo_event"]}'


def compose(path, label="repeat_to_tool", classifier=None):
    classifier = classifier or ScriptedClassifier(label)
    plugin = RepeatAfterMeAnalyzer(classifier)
    coverage = tuple(Coverage(spec.name, "explicitly_adapted", spec.producer) for spec in BUILTIN_EVENTS)
    config = AnalysisConfig(POLICY_JSON, coverage, required_paths=("input.admit", "model.request", "tool.dispatch"))
    registry = Registry(BUILTIN_EVENTS, (plugin.registration(),), producers=frozenset(spec.producer for spec in BUILTIN_EVENTS))
    store = SqliteProvenanceStore(str(path))
    hub = NotificationHub()
    runtime = AnalysisRuntime(config, registry, store, tenant_id="demo", session_id="demo-session", run_id="demo-run", principal_id="demo-user", notifications=hub)
    policy = RepeatAfterMePolicy(config.policy_version)
    security = SecurityConfig(modules=(policy,), analysis=runtime)
    principal = Principal("demo-user", frozenset({"demo"}), frozenset(), "demo-session")
    client = AnalysisClient(runtime.journal, AccessContext(principal.user_id, "demo", frozenset({principal.session_id}), lambda _: True, lambda: True), hub)
    return runtime, security, principal, client
