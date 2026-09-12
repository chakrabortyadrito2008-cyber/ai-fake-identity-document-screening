from core.deployment_readiness import assess


def test_demo_configuration_is_not_marked_ready_for_external_deployment(monkeypatch):
    monkeypatch.delenv("FRAUD_API_KEY", raising=False)
    monkeypatch.delenv("RECEIPT_SIGNING_KEY", raising=False)
    monkeypatch.setenv("FRAUD_ENVIRONMENT", "development")
    result=assess({"api":{"require_api_key":False}}, {"trusted_source":{"mode":"DEMO_ONLY"},"document_anomaly":{"mode":"DEMO_ONLY"},"liveness":{"available":True}})
    assert result["external_deployment_ready"] is False
    assert result["blocking_items"]
