"""Human-in-the-loop operational labels derived from the calibrated risk outcome."""
from __future__ import annotations


# Deterministic sampling share for clean-but-unverified documents. A pixel-perfect
# forgery of a genuinely issued document produces zero fraud signals by nature, so a
# fraction of clean results is always routed to a human. Sampling is keyed on the
# screening inputs' risk score + label context so the decision is reproducible for
# audit (same evidence -> same routing) without leaking anything sensitive.
SAMPLE_RATE_PERCENT = 20


def _sampled_for_review(risk_score: float) -> bool:
    bucket = int(float(risk_score) * 100) % 100
    return bucket < SAMPLE_RATE_PERCENT


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
    if trusted_authority_match:
        return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — NOT VERIFIED", "flagged": False, "reason": "No material fraud signal was detected and an approved non-demo trusted source matched. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
    # Unverified clean document: a careful forgery produces no signals by nature, so a
    # deterministic share is always sampled into human review instead of auto-approval.
    if _sampled_for_review(risk_score):
        return {"code": "MANUAL_VERIFICATION", "label": "NEEDS MANUAL VERIFICATION", "flagged": True, "reason": f"Random audit sampling ({SAMPLE_RATE_PERCENT}% of clean unverified documents): a careful forgery can produce no signals, so clean results without an approved trusted-source match are periodically routed to a human.", "risk_score": risk_score}
    return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — NOT VERIFIED", "flagged": False, "reason": "No material fraud signal was detected and the document fell outside the random audit sample. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
