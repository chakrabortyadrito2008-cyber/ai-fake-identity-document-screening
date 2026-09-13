from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from api.app import create_app
from core.pipeline import FraudPipeline
from core.result_schema import DetectorStatus, EvidenceResult
from core.triage import triage_result


def _document(path: Path):
    image = Image.new("RGB", (900, 600), (180, 180, 180)); draw = ImageDraw.Draw(image)
    draw.rectangle((50, 50, 850, 550), fill=(245, 245, 245), outline=(0, 0, 0), width=4)
    draw.text((110, 120), "BATCH DOCUMENT 123456789", fill=(0, 0, 0), stroke_width=1)
    for y in range(210, 500, 22): draw.line((110, y, 760, y), fill=(80, 80, 80), width=2)
    image.save(path)


def test_operational_triage_labels_are_clear():
    # Clean low-risk documents always auto-classify genuine; only suspicious,
    # high-risk, or insufficient-quality evidence routes to a human.
    assert triage_result("LOW RISK", {"status": "ANALYSABLE"}, 10.50)["code"] == "LIKELY_GENUINE"
    assert triage_result("LOW RISK", {"status": "ANALYSABLE"}, 10.05)["code"] == "LIKELY_GENUINE"
    assert triage_result("REVIEW REQUIRED", {"status": "ANALYSABLE"}, 30)["code"] == "MANUAL_VERIFICATION"
    assert triage_result("HIGH RISK", {"status": "ANALYSABLE"}, 70)["code"] == "LIKELY_FAKE"
    attack = EvidenceResult("liveness", "presentation_attack", DetectorStatus.DETECTED, confidence=.99, severity=32)
    assert triage_result("LOW RISK", {"status": "ANALYSABLE"}, 20, [attack])["code"] == "LIKELY_FAKE"


def test_clean_documents_always_auto_classify_genuine():
    for risk in (0.0, 3.65, 10.05, 10.50, 24.99):
        result = triage_result("LOW RISK", {"status": "ANALYSABLE"}, risk)
        assert result["code"] == "LIKELY_GENUINE"
        assert result["flagged"] is False


def test_trusted_source_match_is_labelled_verified():
    trusted = EvidenceResult("trusted_source", "trusted_validation", DetectorStatus.DETECTED, value="MATCH", confidence=.9, details={"demo_only": False})
    result = triage_result("LOW RISK", {"status": "ANALYSABLE"}, 0.0, [trusted])
    assert result["code"] == "LIKELY_GENUINE"
    assert "trusted source matched" in result["reason"]


def test_exact_reference_match_overrides_ocr_dependent_review():
    """An exact byte match to the reference corpus cannot be tampered; OCR-
    dependent signals on it are reading artifacts, not fraud evidence."""
    reference = EvidenceResult("provenance", "reference_database_match", DetectorStatus.NOT_DETECTED, value={"exact": True, "perceptual_matches": []}, confidence=.95, reliability=.95)
    checksum = EvidenceResult("checksum_validator", "id_checksum_invalid", DetectorStatus.DETECTED, severity=30, confidence=.85, reliability=.9)
    regions = EvidenceResult("manipulation_detection", "inconsistent_image_regions", DetectorStatus.DETECTED, severity=14, confidence=.7, reliability=.7)
    result = triage_result("REVIEW REQUIRED", {"status": "ANALYSABLE"}, 12.8, [reference, checksum, regions])
    assert result["code"] == "LIKELY_GENUINE"
    assert "DATABASE MATCH" in result["label"]


def test_exact_reference_match_does_not_hide_independent_fraud():
    """Real tampering signals (e.g. reuse, deepfake) still escalate even for a
    byte-exact reference document."""
    reference = EvidenceResult("provenance", "reference_database_match", DetectorStatus.NOT_DETECTED, value={"exact": True, "perceptual_matches": []}, confidence=.95, reliability=.95)
    checksum = EvidenceResult("checksum_validator", "id_checksum_invalid", DetectorStatus.DETECTED, severity=30, confidence=.85, reliability=.9)
    deepfake = EvidenceResult("deepfake_detection", "synthetic_or_deepfake_likelihood", DetectorStatus.DETECTED, severity=35, confidence=.9, reliability=.85)
    result = triage_result("REVIEW REQUIRED", {"status": "ANALYSABLE"}, 40, [reference, checksum, deepfake])
    assert result["code"] != "LIKELY_GENUINE"


def test_folder_ingestion_persists_a_report(tmp_path: Path):
    _document(tmp_path / "one.png")
    report = FraudPipeline(Path(__file__).parents[1]).screen_folder(tmp_path, "batch-demo")
    assert report["file_count"] == 1
    assert Path(report["report_path"]).is_file()
    assert report["results"][0]["triage"]["label"]


def test_dashboard_is_served(pipeline_root):
    response = TestClient(create_app(pipeline_root)).get("/")
    assert response.status_code == 200
    assert "AI-Based Fake Identity" in response.text


def test_every_screening_runs_the_full_check_suite(tmp_path: Path):
    """There is a single thorough analysis path: deepfake runs on every document."""
    _document(tmp_path / "one.png")
    result = FraudPipeline(Path(__file__).parents[1]).screen(tmp_path / "one.png")
    deepfake = next(item for item in result["evidence"] if item["detector"] == "deepfake_detection")
    assert deepfake["signal"] != "deepfake_deferred"
    assert deepfake["status"] != "NOT_APPLICABLE"
    assert "analysis_mode" not in result
