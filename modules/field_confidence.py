from __future__ import annotations
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult
class FieldConfidence(Detector):
    name="field_confidence"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        return [EvidenceResult(self.name,"field_confidence",DetectorStatus.NOT_DETECTED,value={"critical_low_confidence":sum(f.confidence<.5 for f in context.fields)},reliability=.7,confidence=.8,dependencies=["ocr"])]
