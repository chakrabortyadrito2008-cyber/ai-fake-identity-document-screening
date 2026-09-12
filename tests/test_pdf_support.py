from pathlib import Path

import fitz

from core.analysis_engine import AnalysisContext
from core.result_schema import DetectorStatus
from modules.input_validator import InputValidator
from modules.preprocessing import Preprocessor


def _pdf(path: Path, pages: int = 2) -> None:
    document = fitz.open()
    for number in range(pages):
        page = document.new_page(width=400, height=250)
        page.insert_text((40, 80), f"Identity document page {number + 1}", fontsize=18)
    document.save(path)
    document.close()


def _config() -> dict:
    return {"supported_extensions": [".pdf"], "max_file_bytes": 1_000_000, "max_pixels": 2_000_000, "processing": {"max_pdf_pages": 5, "pdf_render_dpi": 100}}


def test_multpage_pdf_is_validated_and_rendered(tmp_path: Path):
    path = tmp_path / "document.pdf"
    _pdf(path)
    context = AnalysisContext(path, _config())
    validation = InputValidator().analyse(context)[0]
    assert validation.status == DetectorStatus.NOT_DETECTED
    assert context.metadata["pdf_pages"] == 2
    rendered = Preprocessor().analyse(context)[0]
    assert rendered.status == DetectorStatus.NOT_DETECTED
    assert context.preprocessed is not None
    assert context.metadata["pdf_rendering"]["pages_rendered"] == 2


def test_pdf_page_limit_is_enforced(tmp_path: Path):
    path = tmp_path / "large.pdf"
    _pdf(path, pages=6)
    context = AnalysisContext(path, _config())
    result = InputValidator().analyse(context)[0]
    assert result.status == DetectorStatus.ERROR
    assert result.error_category == "PDF_PAGE_LIMIT"
