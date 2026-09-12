from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class TemporalAnalysis(Detector):
    name="temporal_analysis"
    def __init__(self, repository): self.repository=repository
    def analyse(self, context):
        identity=context.submission.get("identity_key")
        fingerprint=context.metadata.get("fingerprint",{})
        activity=self.repository.recent_activity(identity, fingerprint.get("phash"), seconds=300)
        prior_count=len(self.repository.identity_history(identity)) if identity else 0
        value={**activity,"prior_identity_submissions":prior_count}
        if (identity and activity["identity_submissions"]>=5) or activity["visual_artifact_submissions"]>=5:
            return [EvidenceResult(self.name,"submission_burst",DetectorStatus.DETECTED,value=value,reliability=.72,confidence=.85,severity=20,dependencies=["temporal_history"],details={"reason":"Multiple submissions in a five-minute window; this is an observable rate signal, not a conclusion about intent."})]
        return [EvidenceResult(self.name,"temporal_pattern",DetectorStatus.NOT_DETECTED,value=value,reliability=.65,confidence=.75,dependencies=["temporal_history"])]
