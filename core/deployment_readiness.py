"""Transparent deployment gate: operational demo versus external deployment."""
from __future__ import annotations

import os
from typing import Any


def assess(config: dict[str, Any], capabilities: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    environment=os.getenv("FRAUD_ENVIRONMENT", "development").lower()
    if environment != "production": blockers.append("Set FRAUD_ENVIRONMENT=production for an external deployment.")
    if not config["api"].get("require_api_key"): blockers.append("Enable api.require_api_key and set FRAUD_API_KEY.")
    if not os.getenv("FRAUD_API_KEY"): blockers.append("Set a non-empty FRAUD_API_KEY outside source control.")
    if not os.getenv("RECEIPT_SIGNING_KEY"): blockers.append("Set RECEIPT_SIGNING_KEY to issue server-authenticated analysis receipts.")
    trusted=capabilities.get("trusted_source", {})
    if trusted.get("mode") == "DEMO_ONLY": blockers.append("Replace the demo trusted-source registry with an approved organisational source.")
    anomaly=capabilities.get("document_anomaly", {})
    if anomaly.get("mode") == "DEMO_ONLY": blockers.append("Replace the demo anomaly baseline with a documented, calibrated baseline.")
    if capabilities.get("liveness", {}).get("available"):
        warnings.append("Liveness model is installed but requires a separate live-selfie/video capture flow; it is not run on document portraits.")
    warnings.extend([
        "Deploy behind HTTPS, network access controls and centralised monitoring.",
        "Complete model/data-protection, bias, false-positive and incident-response reviews before production use.",
        "SQLite is suitable for local/single-node deployment; use a managed transactional database for multi-instance deployment.",
    ])
    return {"environment":environment,"external_deployment_ready":not blockers,"blocking_items":blockers,"warnings":warnings}
