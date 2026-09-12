def test_ocr_contract():
    from modules.ocr_engine import OCREngine
    assert OCREngine.name=='ocr_engine'

def test_fast_mode_runs_one_ocr_variant(monkeypatch):
    from types import SimpleNamespace
    import numpy as np
    import modules.ocr_engine as ocr
    monkeypatch.setattr(ocr.shutil, "which", lambda _: "tesseract")
    monkeypatch.setattr(ocr.pytesseract, "get_tesseract_version", lambda: "test")
    calls=[]
    monkeypatch.setattr(ocr.pytesseract, "image_to_data", lambda *args, **kwargs: calls.append(kwargs["config"]) or {"text":["AADHAAR"],"conf":["90"],"left":[0],"top":[0],"width":[10],"height":[10]})
    context=SimpleNamespace(preprocessed=np.zeros((100,100,3),dtype=np.uint8),config={"features":{"ocr":True},"ocr":{"languages":"eng","psm":[6,11]},"processing":{"max_ocr_variants":2}},submission={"analysis_mode":"fast"},metadata={})
    ocr.OCREngine().analyse(context)
    assert calls==["--psm 6"]
