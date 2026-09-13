"""Reference-database (organisation corpus) integration tests."""
import hashlib
import json
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from core.pipeline import FraudPipeline
from database.db_manager import DatabaseManager
from database.reference_ingest import ingest_reference_database
from database.repositories import ScreeningRepository


def _make_card(path: Path, text: str):
    image = Image.new("RGB", (900, 600), (210, 215, 222))
    draw = ImageDraw.Draw(image)
    draw.rectangle((50, 50, 850, 550), fill=(245, 245, 245), outline=(0, 0, 0), width=4)
    draw.text((110, 120), text, fill=(20, 20, 20))
    image.save(path)
    return path


@pytest.fixture
def repo(tmp_path):
    return ScreeningRepository(DatabaseManager(tmp_path / "ref.sqlite3"))


def test_ingest_registers_fingerprints(tmp_path, repo):
    _make_card(tmp_path / "a.png", "DOC A")
    _make_card(tmp_path / "b.png", "DOC B")
    (tmp_path / "notes.txt").write_text("skip me")
    config = {"reference_database_path": str(tmp_path)}
    report = ingest_reference_database(tmp_path, config, repo)
    assert report["available"] is True
    assert report["records"] == 2
    assert report["errors"] == 0
    sha = hashlib.sha256((tmp_path / "a.png").read_bytes()).hexdigest()
    assert repo.is_reference(sha) is True


def test_ingest_is_idempotent(tmp_path, repo):
    _make_card(tmp_path / "a.png", "DOC A")
    config = {"reference_database_path": str(tmp_path)}
    first = ingest_reference_database(tmp_path, config, repo)
    second = ingest_reference_database(tmp_path, config, repo)
    assert first["new"] == 1
    assert second["new"] == 0 and second["unchanged"] == 1
    assert second["records"] == 1


def test_ingest_missing_folder_is_unavailable(tmp_path, repo):
    report = ingest_reference_database(tmp_path, {"reference_database_path": str(tmp_path / "nope")}, repo)
    assert report["available"] is False
    assert report["records"] == 0


def _set_reference_config(pipeline_root: Path, ref_dir: Path | None):
    settings_path = pipeline_root / "config" / "settings.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["reference_database_path"] = str(ref_dir) if ref_dir else ""
    settings_path.write_text(json.dumps(settings), encoding="utf-8")


def _no_reference_config(pipeline_root: Path):
    _set_reference_config(pipeline_root, None)


def test_upload_matching_reference_document_verifies(tmp_path, pipeline_root, monkeypatch):
    """Q1: an upload whose bytes are in the reference database is a database match."""
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    _make_card(ref_dir / "known_doc.png", "AADHAAR 9999 8888 7777")
    _set_reference_config(pipeline_root, ref_dir)
    pipe = FraudPipeline(pipeline_root)
    assert pipe.reference["available"] is True

    result = pipe.screen(_make_card(tmp_path / "upload.png", "AADHAAR 9999 8888 7777"), "holder-1")
    match = next(e for e in result["evidence"] if e["detector"] == "provenance")
    assert match["signal"] == "reference_database_match"
    assert result["triage"]["code"] == "LIKELY_GENUINE"
    assert "DATABASE MATCH" in result["triage"]["label"]


def test_perceptual_match_against_reference(tmp_path, pipeline_root):
    """A re-encoded copy of a reference document still matches (pHash)."""
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    original = _make_card(ref_dir / "known.png", "AADHAAR 5555 4444 3333")
    _set_reference_config(pipeline_root, ref_dir)
    pipe = FraudPipeline(pipeline_root)

    from PIL import ImageEnhance
    copy_path = tmp_path / "recoded.png"
    ImageEnhance.Contrast(Image.open(original)).enhance(1.08).save(copy_path)
    result = pipe.screen(copy_path, "someone")
    match = next(e for e in result["evidence"] if e["detector"] == "provenance")
    assert match["signal"] == "reference_database_match"
    assert match["value"]["exact"] is False


def test_reference_document_never_flags_reuse(tmp_path, pipeline_root):
    """The same registered document screened under two identities stays clean."""
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    card = _make_card(ref_dir / "official.png", "AADHAAR 2345 6789 1238")
    _set_reference_config(pipeline_root, ref_dir)
    pipe = FraudPipeline(pipeline_root)
    first = pipe.screen(card, "person-a")
    second = pipe.screen(card, "person-b")
    for result in (first, second):
        assert result["triage"]["code"] == "LIKELY_GENUINE"
        assert not any(
            e["signal"] in {"exact_artifact_cross_identity_reuse", "silent_artifact_resubmission"}
            for e in result["evidence"] if e["status"] == "DETECTED"
        )


def test_no_reference_folder_configured_still_screens(tmp_path, pipeline_root):
    _no_reference_config(pipeline_root)
    pipe = FraudPipeline(pipeline_root)
    assert pipe.reference["available"] is False
    result = pipe.screen(_make_card(tmp_path / "plain.png", "PLAIN DOC"), "somebody")
    assert result["triage"]["code"] in {"LIKELY_GENUINE", "MANUAL_VERIFICATION"}
