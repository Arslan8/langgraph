from slanggraph_eval.pocs import run_no_defense_pocs


def test_all_local_no_defense_canaries_land() -> None:
    results = run_no_defense_pocs()

    assert len(results) == 8
    assert all(result.condition == "none" for result in results)
    assert all(result.landed for result in results)
