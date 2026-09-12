from core.result_schema import EvidenceResult, DetectorStatus


def _review_actions(evidence: list[EvidenceResult]) -> list[dict]:
    detected = {item.signal for item in evidence if item.status == DetectorStatus.DETECTED}
    unavailable = {item.detector for item in evidence if item.status == DetectorStatus.UNAVAILABLE}
    actions: list[dict] = []
    if "insufficient_quality" in detected:
        actions.append({"priority": "HIGH", "action": "REQUEST_RECAPTURE", "reason": "Obtain a well-lit, sharp original image before relying on downstream checks."})
    if "exact_artifact_cross_identity_reuse" in detected:
        actions.append({"priority": "HIGH", "action": "HOLD_AND_INVESTIGATE_REUSE", "reason": "The exact file hash was previously associated with another submitted identity."})
    if {"face_mismatch", "presentation_attack", "synthetic_or_deepfake_likelihood"} & detected:
        actions.append({"priority": "HIGH", "action": "MANUAL_BIOMETRIC_REVIEW", "reason": "Review source capture and compare against an approved reference; model output is supporting evidence only."})
    if {"qr_content_mismatch", "id_format_invalid", "aadhaar_template_inconsistent"} & detected:
        actions.append({"priority": "MEDIUM", "action": "CHECK_ISSUER_RECORD", "reason": "Validate the document identifier against an approved issuer or organisation source."})
    if "trusted_source" in unavailable:
        actions.append({"priority": "MEDIUM", "action": "CONNECT_APPROVED_TRUSTED_SOURCE", "reason": "No organisation-approved identity source is configured for this screening."})
    if not actions:
        actions.append({"priority": "LOW", "action": "STANDARD_REVIEW_POLICY", "reason": "No high-severity evidence was detected; retain normal human oversight and sampling."})
    return actions


def explain(evidence: list[EvidenceResult], fusion: list[dict] | None = None, risk_score: float | None = None) -> dict:
    detected = [item for item in evidence if item.status == DetectorStatus.DETECTED]
    total = max(0.0, float(risk_score or 0.0))
    drivers = [
        {"dependency_root": item["dependency_root"], "score": item["score"], "risk_share": round(item["score"] / total, 3) if total else 0.0, "signals": item["signals"]}
        for item in sorted(fusion or [], key=lambda entry: entry["score"], reverse=True)
        if item["score"] > 0
    ]
    return {
        "primary_reasons": [item.signal.replace("_", " ") for item in detected if item.severity >= 40],
        "supporting_reasons": [item.signal.replace("_", " ") for item in detected if 0 < item.severity < 40],
        "uncertain_signals": [item.signal for item in evidence if item.status == DetectorStatus.INCONCLUSIVE],
        "unavailable_checks": [item.detector for item in evidence if item.status == DetectorStatus.UNAVAILABLE],
        "evidence_coverage": {
            "conclusive_checks": sum(item.status in {DetectorStatus.DETECTED, DetectorStatus.NOT_DETECTED} for item in evidence),
            "uncertain_checks": sum(item.status == DetectorStatus.INCONCLUSIVE for item in evidence),
            "unavailable_checks": sum(item.status == DetectorStatus.UNAVAILABLE for item in evidence),
            "failed_checks": sum(item.status == DetectorStatus.ERROR for item in evidence),
        },
        "dependency_aware_risk_drivers": drivers,
        "review_playbook": _review_actions(evidence),
    }
