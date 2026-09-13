def test_provenance_contract():
    from modules.provenance import Provenance
    assert Provenance.name=='provenance'

def test_benchmark_identity_namespace_does_not_create_reuse_alert():
    from types import SimpleNamespace
    from modules.provenance import Provenance
    class Repository:
        def history(self, sha): return {"identities":["autotest:prior-run"]}
        def similar_phashes(self, phash, max_distance): return []
    context=SimpleNamespace(metadata={"fingerprint":{"sha256":"a","phash":"0"*16}},submission={"identity_key":"benchmark:dataset:file"},config={})
    result=Provenance(Repository()).analyse(context)[0]
    assert result.signal=="artifact_history"

def test_database_match_with_trusted_source_is_positive_evidence():
    """Q1: a database record + trusted source match corroborates the document."""
    from types import SimpleNamespace
    from modules.provenance import Provenance
    from core.result_schema import DetectorStatus
    class Repository:
        def history(self, sha): return {"identities":["person-1"],"appearances":3}
        def similar_phashes(self, phash, max_distance): return []
    context=SimpleNamespace(metadata={"fingerprint":{"sha256":"a","phash":"0"*16},"trusted_source_match":True},submission={"identity_key":"person-1"},config={})
    result=Provenance(Repository()).analyse(context)[0]
    assert result.signal=="artifact_history_verified"
    assert result.status==DetectorStatus.NOT_DETECTED

def test_silent_resubmission_without_identity_is_detected():
    from types import SimpleNamespace
    from modules.provenance import Provenance
    from core.result_schema import DetectorStatus
    class Repository:
        def history(self, sha): return {"identities":["person-1"],"appearances":2}
        def similar_phashes(self, phash, max_distance): return []
    context=SimpleNamespace(metadata={"fingerprint":{"sha256":"a","phash":"0"*16}},submission={"identity_key":None},config={})
    result=Provenance(Repository()).analyse(context)[0]
    assert result.signal=="silent_artifact_resubmission"
    assert result.status==DetectorStatus.DETECTED

def test_near_duplicate_matches_surface_for_review():
    """Q3: tiny invisible difference vs a stored document must produce evidence."""
    from types import SimpleNamespace
    from modules.provenance import Provenance
    from core.result_schema import DetectorStatus
    class Repository:
        def history(self, sha): return None
        def similar_phashes(self, phash, max_distance): return [{"sha256":"b"*64,"phash":hex(int(phash,16)^3)[2:].zfill(16),"appearances":1}]
    context=SimpleNamespace(metadata={"fingerprint":{"sha256":"a"*64,"phash":"0"*16}},submission={"identity_key":"new-person"},config={})
    result=Provenance(Repository()).analyse(context)[0]
    assert result.signal=="near_duplicate_artifact"
    assert result.status==DetectorStatus.DETECTED
    assert result.value["related_sha256"]==["b"*64]
