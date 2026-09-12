from core.evidence_fusion import EvidenceFusion
from core.result_schema import EvidenceResult,DetectorStatus
def test_dependent_evidence_is_discounted():
    e=[EvidenceResult('a','one',DetectorStatus.DETECTED,reliability=1,confidence=1,severity=40,dependencies=['ocr']),EvidenceResult('b','two',DetectorStatus.DETECTED,reliability=1,confidence=1,severity=40,dependencies=['ocr'])]
    assert EvidenceFusion().fuse(e)[0]==50
