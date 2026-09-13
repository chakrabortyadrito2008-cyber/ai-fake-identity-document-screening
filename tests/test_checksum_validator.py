from types import SimpleNamespace

from modules.checksum_validator import ChecksumValidator, verhoeff_check_digit, verhoeff_valid


def _context(fields, doc_type="AADHAAR"):
    return SimpleNamespace(
        fields=fields,
        metadata={"document_type": {"value": doc_type}},
    )


def _field(normalized):
    return SimpleNamespace(name="id_number", normalized_value=normalized, value=normalized)


def test_derived_check_digit_passes_and_others_fail():
    check = verhoeff_check_digit("23456789123")
    assert check is not None
    valid_number = "23456789123" + check
    assert verhoeff_valid(valid_number)
    wrong = "23456789123" + ("0" if check != "0" else "1")
    assert not verhoeff_valid(wrong)


def test_common_placeholder_sequences_fail():
    for fabricated in ("123456789012", "000000000000", "111111111111", "234567891234"):
        assert not verhoeff_valid(fabricated)


def test_fabricated_aadhaar_raises_checksum_evidence():
    result = ChecksumValidator().analyse(_context([_field("123456789012")]))[0]
    assert result.signal == "id_checksum_invalid"
    assert result.status.value == "DETECTED"
    assert result.severity >= 20


def test_checksummed_aadhaar_is_not_flagged():
    check = verhoeff_check_digit("23456789123")
    result = ChecksumValidator().analyse(_context([_field("23456789123" + check)]))[0]
    assert result.status.value == "NOT_DETECTED"


def test_pan_holder_type_is_enforced():
    valid = ChecksumValidator().analyse(_context([_field("ABCPR1234F")], doc_type="PAN"))[0]
    assert valid.status.value == "NOT_DETECTED"
    invalid = ChecksumValidator().analyse(_context([_field("ABCDR1234F")], doc_type="PAN"))[0]
    assert invalid.signal == "pan_holder_type_invalid"


def test_no_identifier_is_not_applicable():
    result = ChecksumValidator().analyse(_context([]))[0]
    assert result.status.value == "NOT_APPLICABLE"


def test_unknown_document_type_does_not_score():
    result = ChecksumValidator().analyse(_context([_field("123456789012")], doc_type="UNKNOWN"))[0]
    assert result.status.value == "NOT_DETECTED"


def test_probable_aadhaar_without_brand_keyword_still_validated():
    """Stylized headers often defeat OCR brand reading; the checksum must still run."""
    result = ChecksumValidator().analyse(_context([_field("123456789012")], doc_type="AADHAAR_PROBABLE"))[0]
    assert result.signal == "id_checksum_invalid"
    assert result.status.value == "DETECTED"
    assert result.severity == 25  # lower than confirmed-Aadhaar severity (30)
    assert result.details["type_basis"].startswith("12-digit number + government marker")


def test_probable_aadhaar_with_valid_checksum_is_clean():
    check = verhoeff_check_digit("23456789123")
    result = ChecksumValidator().analyse(_context([_field("23456789123" + check)], doc_type="AADHAAR_PROBABLE"))[0]
    assert result.status.value == "NOT_DETECTED"
