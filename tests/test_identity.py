from modules.field_normalizer import normalize_id
def test_identifier_normalization():
    assert normalize_id('abc 12-3','pan')=='ABC123'
    assert normalize_id('123O 12I3 456B','aadhaar')=='123012134568'
