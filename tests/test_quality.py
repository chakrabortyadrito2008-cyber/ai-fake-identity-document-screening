from core.evidence_fusion import RiskEngine
from core.result_schema import Outcome
def test_insufficient_quality_is_not_high_risk():
    assert RiskEngine({'risk':{'review_threshold':25,'high_threshold':60}}).evaluate(0,False,0)[0] == Outcome.INSUFFICIENT
