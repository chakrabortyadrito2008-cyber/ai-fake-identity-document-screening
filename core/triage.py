"""Human-in-the-loop operational labels derived from the calibrated risk outcome."""
from __future__ import annotations


def triage_result(outcome: str, quality: dict, risk_score: float, evidence: list | None = None) -> dict:
    evidence = evidence or []
    detected = [item for item in evidence if getattr(item, "status", None).value == "DETECTED"]
    strong_attack = any(item.signal in {"exact_artifact_cross_identity_reuse", "presentation_attack", "synthetic_or_deepfake_likelihood"} and item.confidence >= .8 for item in detected)
    trusted_authority_match = any(item.detector == "trusted_source" and item.value == "MATCH" and not item.details.get("demo_only", False) for item in evidence)
    quality_state = quality.get("status")
    if quality_state == "INSUFFICIENT_QUALITY" or outcome == "INSUFFICIENT EVIDENCE":
        return {"code": "MANUAL_VERIFICATION", "label": "NEEDS MANUAL VERIFICATION", "flagged": True, "reason": "Image quality or evidence coverage is insufficient for a reliable automated triage."}
    if outcome == "HIGH RISK" or strong_attack:
        return {"code": "LIKELY_FAKE", "label": "LIKELY FAKE / FRAUD SIGNALS", "flagged": True, "reason": "High-confidence fraud or presentation-attack evidence was detected. Hold the document for manual confirmation."}
    if outcome == "REVIEW REQUIRED":
        return {"code": "MANUAL_VERIFICATION", "label": "NEEDS MANUAL VERIFICATION", "flagged": True, "reason": "Suspicious or conflicting evidence requires a reviewer decision."}
    reason = "No material fraud signal was detected."
    if trusted_authority_match:
        reason = "No material fraud signal was detected and an approved non-demo trusted source matched. This remains a screening outcome, not legal verification."
    return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — NOT VERIFIED", "flagged": False, "reason": reason, "risk_score": risk_score}
