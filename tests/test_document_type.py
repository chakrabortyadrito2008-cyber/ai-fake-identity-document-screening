def test_type_contract():
    from modules.document_type import DocumentTypeDetector
    assert DocumentTypeDetector.name=='document_type'

def test_aadhaar_type_uses_multiple_non_sensitive_markers():
    from types import SimpleNamespace
    from modules.document_type import DocumentTypeDetector
    context=SimpleNamespace(metadata={"ocr":{"raw_text":"Aadhaar Government of India Date of Birth"}})
    result=DocumentTypeDetector().analyse(context)[0]
    assert result.value["value"]=="AADHAAR"

def test_aadhaar_type_tolerates_common_ocr_spelling_variation():
    from types import SimpleNamespace
    from modules.document_type import DocumentTypeDetector
    context=SimpleNamespace(metadata={"ocr":{"raw_text":"Aadhar Government Date of Birth"}})
    assert DocumentTypeDetector().analyse(context)[0].value["value"]=="AADHAAR"
