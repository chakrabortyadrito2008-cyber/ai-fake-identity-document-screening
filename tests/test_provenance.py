def test_provenance_contract():
    from modules.provenance import Provenance
    assert Provenance.name=='provenance'

def test_benchmark_identity_namespace_does_not_create_reuse_alert():
    from types import SimpleNamespace
    from modules.provenance import Provenance
    class Repository:
        def history(self, sha): return {"identities":["autotest:prior-run"]}
    context=SimpleNamespace(metadata={"fingerprint":{"sha256":"a"}},submission={"identity_key":"benchmark:dataset:file"})
    result=Provenance(Repository()).analyse(context)[0]
    assert result.signal=="artifact_history"
