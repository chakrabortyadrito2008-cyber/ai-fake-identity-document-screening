from core.analysis_receipt import build_receipt, verify_digest
from core.result_schema import DetectorStatus, EvidenceResult
from modules.explanation import explain


def test_receipt_digest_is_verifiable_and_model_attested():
    result = {
        "screening_id": "screen-1", "timestamp": "2026-01-01T00:00:00+00:00", "status": "LOW RISK", "risk_score": 0,
        "fingerprints": {"sha256": "a" * 64, "phash": "abc"}, "versions": {"software": "1.1.0", "config": "1.0.0"},
        "evidence": [{"detector": "quality", "signal": "quality", "status": "NOT_DETECTED", "confidence": 1, "severity": 0, "dependencies": []}],
    }
    receipt = build_receipt(result, {"model": {"version": "v1", "sha256": "b" * 64, "integrity_verified": True, "load_status": "READY"}})
    assert receipt["models"][0]["integrity_verified"] is True
    assert verify_digest(receipt) is True
    receipt["risk_score"] = 99
    assert verify_digest(receipt) is False


def test_explanation_has_actionable_dependency_aware_review_plan():
    evidence = [EvidenceResult("provenance", "exact_artifact_cross_identity_reuse", DetectorStatus.DETECTED, severity=75, confidence=.98, reliability=.98, dependencies=["artifact_sha"])]
    explanation = explain(evidence, [{"dependency_root": "artifact_sha", "score": 72, "signals": ["exact_artifact_cross_identity_reuse"]}], 72)
    assert explanation["dependency_aware_risk_drivers"][0]["risk_share"] == 1.0
    assert explanation["review_playbook"][0]["action"] == "HOLD_AND_INVESTIGATE_REUSE"
