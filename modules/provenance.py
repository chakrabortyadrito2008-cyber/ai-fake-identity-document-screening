from __future__ import annotations
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class Provenance(Detector):
    name="provenance"
    def __init__(self, repository): self.repository=repository
    def analyse(self, context):
        sha=context.metadata["fingerprint"]["sha256"]; prior=self.repository.history(sha); identity=context.submission.get("identity_key")
        context.metadata["provenance"]=prior or {"first_seen":None,"appearances":0,"identities":[]}
        # Test/benchmark identities are namespace-scoped so repeated automated
        # regression runs do not masquerade as real cross-person reuse.
        internal=lambda value: isinstance(value,str) and value.startswith(("autotest:","autotest-fast:","benchmark:"))
        prior_identities=[value for value in (prior or {}).get("identities",[]) if value != "UNKNOWN" and not internal(value)]
        if prior and identity and not internal(identity) and identity not in prior_identities and prior_identities:
            return [EvidenceResult(self.name,"exact_artifact_cross_identity_reuse",DetectorStatus.DETECTED,value={"prior_identity_count":len(prior_identities)},reliability=.98,confidence=.98,severity=75,dependencies=["artifact_sha"])]
        return [EvidenceResult(self.name,"artifact_history",DetectorStatus.NOT_DETECTED,value=context.metadata["provenance"],reliability=.9,confidence=.9,dependencies=["artifact_sha"])]
