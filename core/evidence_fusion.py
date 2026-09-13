from __future__ import annotations
from collections import defaultdict
from core.result_schema import DetectorStatus, EvidenceResult, Outcome


class EvidenceFusion:
    """Groups dependent signals before scoring so an OCR chain is not tripled."""
    def fuse(self, evidence: list[EvidenceResult], max_single_evidence: float | None = None) -> tuple[float, list[dict]]:
        groups: dict[str, list[EvidenceResult]]=defaultdict(list)
        for e in evidence:
            if e.status != DetectorStatus.DETECTED or e.severity <= 0: continue
            groups[(e.dependencies or [e.detector])[0]].append(e)
        total=0.0; summaries=[]
        for root, items in groups.items():
            scores=sorted(
                (min(max_single_evidence, max(0, e.severity)) if max_single_evidence is not None else max(0, e.severity))
                * max(0, e.confidence) * max(0, e.reliability)
                for e in items
            )
            scores.reverse()
            group_score=scores[0] + sum(scores[1:])*0.25 if scores else 0
            total+=group_score
            summaries.append({"dependency_root":root,"score":round(group_score,2),"signals":[i.signal for i in items]})
        return min(100.0,total), summaries


class RiskEngine:
    """Maps a fused risk score to a screening outcome and confidence label."""
    def __init__(self, settings: dict): self.settings=settings
    def evaluate(self, score: float, analysable: bool, evidence_count: int) -> tuple[Outcome, str]:
        r=self.settings["risk"]
        # Poor image quality reduces certainty rather than creating suspicion. Strong
        # independent artifact evidence can still be retained and escalated.
        if not analysable and score < r["high_threshold"]: return Outcome.INSUFFICIENT, "LOW"
        if score >= r["high_threshold"]: return Outcome.HIGH_RISK, "HIGH"
        if score >= r["review_threshold"]: return Outcome.REVIEW, "MEDIUM"
        return Outcome.LOW_RISK, "LOW" if evidence_count < 2 else "MEDIUM"
