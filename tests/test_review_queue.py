from pathlib import Path

from PIL import Image
from fastapi.testclient import TestClient

from api.app import create_app
from core.pipeline import FraudPipeline


def test_review_decision_is_separate_from_immutable_screening(pipeline_root: Path, tmp_path: Path):
    image=tmp_path / "document.png"; Image.new("RGB", (800, 600), "white").save(image)
    pipeline=FraudPipeline(pipeline_root)
    result=pipeline.screen(image, "case-review")
    before=pipeline.repo.screening(result["screening_id"])
    decision=pipeline.repo.record_review_decision(result["screening_id"], "ESCALATED", "analyst-7", "Needs issuer check")
    after=pipeline.repo.screening(result["screening_id"])
    assert decision["decision"] == "ESCALATED"
    assert before == after
    assert pipeline.repo.review_queue(include_resolved=True)[0]["review"]["decision"] == "ESCALATED"


def test_operations_and_review_api(pipeline_root: Path, tmp_path: Path):
    image=tmp_path / "document.png"; Image.new("RGB", (800, 600), "white").save(image)
    pipeline=FraudPipeline(pipeline_root); result=pipeline.screen(image, "case-api")
    client=TestClient(create_app(pipeline_root))
    assert client.get("/operations/overview").status_code == 200
    response=client.post(f"/screen/{result['screening_id']}/review", data={"decision":"REJECTED","notes":"Confirmed fake"}, headers={"X-Operator-ID":"analyst-9"})
    assert response.status_code == 200
    assert response.json()["reviewer_id"] == "analyst-9"
    assert "AI-Based Fake Identity" in client.get("/").text
