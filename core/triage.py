"""Human-in-the-loop operational labels derived from the calibrated risk outcome."""
from __future__ import annotations

# Signals driven by OCR accuracy or image-capture quality. An exact byte match
# to the organisation's reference corpus rules out tampering, so these signals
# cannot force a registered document into manual review.
OCR_DEPENDENT_SIGNALS = {"id_checksum_invalid", "id_format_invalid", "inconsistent_image_regions", "cross_document_field_contradiction"}


def triage_result(outcome: str, quality: dict, risk_score: float, evidence: list | None = None) -> dict:
    evidence = evidence or []
    detected = [item for item in evidence if getattr(item, "status", None).value == "DETECTED"]
    strong_attack = any(item.signal in {"exact_artifact_cross_identity_reuse", "silent_artifact_resubmission", "presentation_attack", "synthetic_or_deepfake_likelihood"} and item.confidence >= .8 for item in detected)
    trusted_authority_match = any(item.detector == "trusted_source" and item.value == "MATCH" and not item.details.get("demo_only", False) for item in evidence)
    reference_database_match = any(item.detector == "provenance" and item.signal == "reference_database_match" for item in evidence)
    quality_state = quality.get("status")
    if quality_state == "INSUFFICIENT_QUALITY" or outcome == "INSUFFICIENT EVIDENCE":
        return {"code": "MANUAL_VERIFICATION", "label": "NEEDS MANUAL VERIFICATION", "flagged": True, "reason": "Image quality or evidence coverage is insufficient for a reliable automated triage."}
    if outcome == "HIGH RISK" or strong_attack:
        return {"code": "LIKELY_FAKE", "label": "LIKELY FAKE — AUTO-DECLARED", "flagged": True, "reason": "High-confidence fraud or presentation-attack evidence was detected. The document is automatically classified fake."}
    exact_reference_match = any(
        item.detector == "provenance" and item.signal == "reference_database_match" and (item.value or {}).get("exact")
        for item in evidence
    )
    if exact_reference_match and outcome == "REVIEW REQUIRED":
        review_drivers = {item.signal for item in detected if item.severity > 0}
        if review_drivers and review_drivers <= OCR_DEPENDENT_SIGNALS:
            return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — DATABASE MATCH", "flagged": False, "reason": "The document byte-exactly matches the organisation reference database; the remaining signals are OCR-accuracy artifacts on a known document. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
    if outcome == "REVIEW REQUIRED":
        return {"code": "MANUAL_VERIFICATION", "label": "NEEDS MANUAL VERIFICATION", "flagged": True, "reason": "Suspicious or conflicting evidence requires a reviewer decision."}
    if trusted_authority_match:
        return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — VERIFIED SOURCE", "flagged": False, "reason": "No material fraud signal was detected and an approved non-demo trusted source matched. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
    if reference_database_match:
        return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — DATABASE MATCH", "flagged": False, "reason": "No material fraud signal was detected and the document is registered in the organisation reference database. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
    return {"code": "LIKELY_GENUINE", "label": "LIKELY GENUINE — NOT VERIFIED", "flagged": False, "reason": "No material fraud signal was detected. This remains a screening outcome, not legal verification.", "risk_score": risk_score}
