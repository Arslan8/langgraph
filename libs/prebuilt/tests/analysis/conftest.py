"""Keep fixture guarded tools out of the existing process-wide inventory."""

import pytest

from langgraph.prebuilt.security.introspect import _unregister_guarded_tool


@pytest.fixture(autouse=True)
def clean_analysis_tool_inventory():
    yield
    for name in (
        "record_analysis_test",
        "denied_analysis_test",
        "fixed_test",
        "interpreter_sink",
        "record_demo_event",
    ):
        _unregister_guarded_tool(name)
