"""Effective-policy verification must reject widened native authority."""

import copy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "openshell_native", Path(__file__).resolve().parents[1] / "remaining/openshell_native.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_omitted_defaults_are_accepted_but_widening_is_rejected():
    expected = {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": False,
            "read_only": ["/fixture/allowed"],
            "read_write": [],
        },
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": "sandbox", "run_as_group": "sandbox"},
    }
    actual = {"status": "effective", "policy": copy.deepcopy(expected)}
    del actual["policy"]["filesystem_policy"]["read_write"]
    assert module.policy_matches(actual, expected)
    for key, value in [("read_only", ["/"]), ("read_write", ["/tmp"]), ("include_workdir", True)]:
        changed = copy.deepcopy(actual)
        changed["policy"]["filesystem_policy"][key] = value
        assert not module.policy_matches(changed, expected)
    changed = copy.deepcopy(actual)
    changed["policy"]["landlock"]["compatibility"] = "best_effort"
    assert not module.policy_matches(changed, expected)
    changed = copy.deepcopy(actual)
    changed["policy"]["network_policies"] = {"extra": {}}
    assert not module.policy_matches(changed, expected)
    assert not module.policy_matches({**actual, "status": "pending"}, expected)
