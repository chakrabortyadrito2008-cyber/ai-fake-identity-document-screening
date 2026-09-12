from pathlib import Path

import numpy as np

from core.analysis_engine import AnalysisContext
from core.result_schema import DetectorStatus, FieldValue
from database.db_manager import DatabaseManager
from database.repositories import ScreeningRepository
from modules.attack_detection import AttackDetection
from modules.cross_document_consistency import CrossDocumentConsistency
from modules.document_layout import DocumentLayout
from modules.graph_analysis import GraphAnalysis
from modules.manipulation_detection import ManipulationDetection


def _repository(tmp_path: Path) -> ScreeningRepository:
    return ScreeningRepository(DatabaseManager(tmp_path / "completion.sqlite3"))


def _record(repository: ScreeningRepository, sha: str, identity: str, fields: list[dict]) -> None:
    repository.record(sha, "a" * 16, identity, "LOW RISK", 0, {
        "identity": {"fields": fields}, "versions": {"config": "test"}, "triage": {},
    })


def test_layout_creates_coordinate_regions():
    image = np.full((300, 600, 3), 180, dtype=np.uint8)
    context = AnalysisContext(Path("document.png"), {}, preprocessed=image, metadata={"ocr": {"tokens": [{"text": "Name", "confidence": 95, "box": [20, 30, 70, 20]}]}})
    evidence = DocumentLayout().analyse(context)[0]
    assert evidence.status == DetectorStatus.NOT_DETECTED
    assert context.metadata["regions"]["orientation"] == "LANDSCAPE"
    assert context.metadata["regions"]["text_regions"][0]["box"] == [20, 30, 70, 20]


def test_cross_document_detects_normalized_contradiction(tmp_path: Path):
    repository = _repository(tmp_path)
    _record(repository, "a" * 64, "person-1", [{"name": "date_of_birth", "normalized_value": "2000-01-01"}])
    context = AnalysisContext(Path("document.png"), {}, fields=[FieldValue("date_of_birth", "2001-01-01", "2001-01-01", .9)], submission={"identity_key": "person-1"})
    evidence = CrossDocumentConsistency(repository).analyse(context)[0]
    assert evidence.status == DetectorStatus.DETECTED
    assert evidence.signal == "cross_document_field_contradiction"


def test_graph_uses_persisted_field_relationships(tmp_path: Path):
    repository = _repository(tmp_path)
    _record(repository, "b" * 64, "person-1", [{"name": "name", "normalized_value": "SAM TEST"}])
    context = AnalysisContext(Path("document.png"), {"features": {"graph": True}, "processing": {"max_graph_nodes": 100}}, fields=[FieldValue("name", "Sam Test", "SAM TEST", .9)], metadata={"fingerprint": {"sha256": "c" * 64}}, submission={"identity_key": "person-2"})
    evidence = GraphAnalysis(repository).analyse(context)[0]
    assert evidence.status == DetectorStatus.DETECTED
    assert evidence.value["related_artifacts"] == 1
    assert evidence.value["related_identities"] == 2


def test_attack_detection_uses_persisted_short_window_telemetry(tmp_path: Path):
    repository = _repository(tmp_path)
    for index in range(8):
        _record(repository, f"{index:064x}", "person-1", [])
    context = AnalysisContext(Path("document.png"), {}, metadata={"fingerprint": {"phash": "b" * 16}}, submission={"identity_key": "person-1"})
    evidence = AttackDetection(repository).analyse(context)[0]
    assert evidence.status == DetectorStatus.DETECTED
    assert evidence.signal == "automated_submission_burst"


def test_manipulation_detector_returns_real_regional_measurements():
    image = np.full((320, 640, 3), 128, dtype=np.uint8)
    image[80:160, 80:160] = np.random.default_rng(3).integers(0, 255, (80, 80, 3), dtype=np.uint8)
    context = AnalysisContext(Path("document.png"), {}, preprocessed=image)
    evidence = ManipulationDetection().analyse(context)[0]
    assert evidence.status in {DetectorStatus.DETECTED, DetectorStatus.NOT_DETECTED}
    assert evidence.value["grid_cells"] >= 4
