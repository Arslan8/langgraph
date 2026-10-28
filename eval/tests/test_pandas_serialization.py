"""The explicit serialization adaptation preserves nested values across JSON."""

import importlib.util
import json
from pathlib import Path

import pytest

pd = pytest.importorskip("pandas")
np = pytest.importorskip("numpy")
spec = importlib.util.spec_from_file_location(
    "sandbox_codec", Path(__file__).resolve().parents[1] / "apps/pandas/sandbox_codec.py"
)
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


def test_nested_dataframe_and_scalar_results():
    frame = pd.DataFrame(
        {"date": [pd.Timestamp("2026-01-05"), pd.NaT], "sales": [100.0, float("nan")]}
    )
    result = codec._to_jsonable([frame, {"count": np.int64(1), "missing": pd.NA}])
    assert json.loads(json.dumps(result, allow_nan=False)) == [
        {"date": {"0": "2026-01-05T00:00:00", "1": None}, "sales": {"0": 100.0, "1": None}},
        {"count": 1, "missing": None},
    ]


def test_no_silent_loss_or_placeholder_for_unsupported_values():
    with pytest.raises(ValueError, match="collision"):
        codec._to_jsonable({1: "a", "1": "b"})
    with pytest.raises(TypeError, match="Unsupported"):
        codec._to_jsonable(object())


def test_period_values_and_indexes_are_explicitly_versioned():
    frame = pd.DataFrame({"month": [pd.Period("2026-01", freq="M")], "total": [5]})
    for version in ["recursive-json-v1", "recursive-json-v2"]:
        module = {}
        exec(codec.repair_runner("def _to_jsonable(obj): return obj", version), module)
        if version == "recursive-json-v1":
            with pytest.raises(TypeError, match="Period"):
                module["_to_jsonable"](frame)
        else:
            assert module["_to_jsonable"](frame) == {"month": {"0": "2026-01"}, "total": {"0": 5}}
            assert module["_to_jsonable"](frame.set_index("month")) == {"total": {"2026-01": 5}}


def test_repair_preserves_other_runner_functions():
    source = "def _to_jsonable(obj): return 'broken'\ndef guard(): raise PermissionError('blocked')"
    module = {}
    exec(codec.repair_runner(source), module)
    assert module["_to_jsonable"](pd.Timestamp("2026-01-05")) == "2026-01-05T00:00:00"
    with pytest.raises(PermissionError, match="blocked"):
        module["guard"]()
    with pytest.raises(ValueError, match="layout"):
        codec.repair_runner("pass")
