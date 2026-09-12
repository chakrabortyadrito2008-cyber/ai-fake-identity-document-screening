from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class AttackDetection(Detector):
    name = "attack_detection"

    def __init__(self, repository=None):
        self.repository = repository

    def analyse(self, context):
        if self.repository is None:
            return [EvidenceResult(self.name, "automated_attack", DetectorStatus.NOT_APPLICABLE, details={"reason": "Submission repository unavailable"})]
        identity = context.submission.get("identity_key")
        fingerprint = context.metadata.get("fingerprint", {})
        activity = self.repository.recent_activity(identity, fingerprint.get("phash"), seconds=60)
        # A very short-window burst is technically observable.  It is kept
        # distinct from temporal history so fusion treats correlated timing
        # evidence as one dependency root.
        burst = activity["total_submissions"] >= 20 or (identity and activity["identity_submissions"] >= 8) or activity["visual_artifact_submissions"] >= 8
        if burst:
            return [EvidenceResult(self.name, "automated_submission_burst", DetectorStatus.DETECTED, value=activity, reliability=.78, confidence=.88, severity=26, dependencies=["temporal_history"], details={"reason": "Short-window submission volume exceeded configured conservative thresholds; intent is not inferred."})]
        return [EvidenceResult(self.name, "automated_attack", DetectorStatus.NOT_DETECTED, value=activity, reliability=.7, confidence=.8, dependencies=["temporal_history"])]
