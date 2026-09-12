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
    assert triage_result("LOW RISK", {"status": "ANALYSABLE"}, 0)["code"] == "MANUAL_VERIFICATION"
    assert triage_result("REVIEW REQUIRED", {"status": "ANALYSABLE"}, 30)["code"] == "MANUAL_VERIFICATION"
    assert triage_result("HIGH RISK", {"status": "ANALYSABLE"}, 70)["code"] == "LIKELY_FAKE"
    attack = EvidenceResult("liveness", "presentation_attack", DetectorStatus.DETECTED, confidence=.99, severity=32)
    assert triage_result("LOW RISK", {"status": "ANALYSABLE"}, 20, [attack])["code"] == "LIKELY_FAKE"


def test_folder_ingestion_persists_a_report(tmp_path: Path):
    _document(tmp_path / "one.png")
    report = FraudPipeline(Path(__file__).parents[1]).screen_folder(tmp_path, "batch-demo")
    assert report["file_count"] == 1
    assert report["analysis_mode"] == "fast"
    assert Path(report["report_path"]).is_file()
    assert report["results"][0]["triage"]["label"]


def test_dashboard_is_served(pipeline_root):
    response = TestClient(create_app(pipeline_root)).get("/")
    assert response.status_code == 200
    assert "AI-Based Fake Identity" in response.text


def test_fast_mode_defers_deepfake_for_batch_throughput(tmp_path: Path):
    _document(tmp_path / "one.png")
    result = FraudPipeline(Path(__file__).parents[1]).screen(tmp_path / "one.png", analysis_mode="fast")
    deepfake = next(item for item in result["evidence"] if item["detector"] == "deepfake_detection")
    assert deepfake["signal"] == "deepfake_deferred"
    assert deepfake["status"] == "NOT_APPLICABLE"
