from pathlib import Path

import numpy as np

from core.analysis_engine import AnalysisContext
from modules.aadhaar_template import AadhaarTemplate


def test_aadhaar_template_accepts_expected_layout():
    root = Path(__file__).parents[1]
    config = {"_root": str(root)}
    context = AnalysisContext(Path("sample.png"), config, preprocessed=np.zeros((632, 1015, 3), dtype=np.uint8))
    context.metadata["document_type"] = {"value": "AADHAAR"}
    context.metadata["ocr"] = {"raw_text": "Aadhaar Government of India Date of Birth Aadhaar is proof"}
    context.metadata["faces"] = [{"box": [110, 150, 150, 200]}]
    result = AadhaarTemplate().analyse(context)[0]
    assert result.status.value == "NOT_DETECTED"


def test_aadhaar_template_flags_major_layout_mismatch():
    root = Path(__file__).parents[1]
    context = AnalysisContext(Path("sample.png"), {"_root": str(root)}, preprocessed=np.zeros((600, 600, 3), dtype=np.uint8))
    context.metadata["document_type"] = {"value": "AADHAAR"}
    context.metadata["ocr"] = {"raw_text": "Aadhaar Government of India"}
    result = AadhaarTemplate().analyse(context)[0]
    assert result.status.value == "DETECTED"
