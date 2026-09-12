def test_semantic_rule():
    from core.result_schema import Outcome
    assert Outcome.LOW_RISK.value != 'genuine'
