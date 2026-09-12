from __future__ import annotations
from core.result_schema import Outcome

class RiskEngine:
    def __init__(self, settings: dict): self.settings=settings
    def evaluate(self, score: float, analysable: bool, evidence_count: int) -> tuple[Outcome, str]:
        r=self.settings["risk"]
        # Poor image quality reduces certainty rather than creating suspicion. Strong
        # independent artifact evidence can still be retained and escalated.
        if not analysable and score < r["high_threshold"]: return Outcome.INSUFFICIENT, "LOW"
        if score >= r["high_threshold"]: return Outcome.HIGH_RISK, "HIGH"
        if score >= r["review_threshold"]: return Outcome.REVIEW, "MEDIUM"
        return Outcome.LOW_RISK, "LOW" if evidence_count < 2 else "MEDIUM"
