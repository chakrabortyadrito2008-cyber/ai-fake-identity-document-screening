from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class BehaviouralAnalysis(Detector):
    name="behavioural_analysis"
    def analyse(self, context): return [EvidenceResult(self.name,"behaviour",DetectorStatus.NOT_APPLICABLE,details={"reason":"No privacy-minimised session telemetry supplied"})]
