from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class ArtifactIntelligence(Detector):
    name="artifact_intelligence"
    def __init__(self, repository): self.repository=repository
    def analyse(self, context):
        p=context.metadata.get("provenance",{}); state="NEW" if not p.get("first_seen") else "NEUTRAL"
        fp=context.metadata.get("fingerprint",{}).get("phash")
        matches=self.repository.similar_phashes(fp,context.config["phash_distance_threshold"]) if fp else []
        return [EvidenceResult(self.name,"template_reputation",DetectorStatus.NOT_DETECTED,value={"reputation":state,"similar_artifacts":len(matches)},reliability=.4,confidence=.5,dependencies=["artifact_phash"],details={"similarity_is_not_identity":True,"index_note":"bounded SQLite fallback"})]
