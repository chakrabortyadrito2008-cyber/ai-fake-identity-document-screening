"""Portable integrity receipt for a completed screening result.

The digest supports accidental-change detection.  When RECEIPT_SIGNING_KEY is
configured, an HMAC provides server-origin authentication without storing the
secret in the result or database payload.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_receipt(result: dict[str, Any], configured_models: dict[str, Any]) -> dict[str, Any]:
    evidence_summary = [
        {
            "detector": item.get("detector"),
            "signal": item.get("signal"),
            "status": item.get("status"),
            "confidence": item.get("confidence"),
            "severity": item.get("severity"),
            "dependencies": item.get("dependencies", []),
        }
        for item in result.get("evidence", [])
    ]
    model_attestations = [
        {
            "name": name,
            "version": model.get("version"),
            "sha256": model.get("sha256"),
            "integrity_verified": bool(model.get("integrity_verified")),
            "load_status": model.get("load_status"),
        }
        for name, model in sorted(configured_models.items())
    ]
    payload = {
        "receipt_version": "1.0",
        "screening_id": result.get("screening_id"),
        "timestamp": result.get("timestamp"),
        "input_sha256": result.get("fingerprints", {}).get("sha256"),
        "input_phash": result.get("fingerprints", {}).get("phash"),
        "outcome": result.get("status"),
        "risk_score": result.get("risk_score"),
        "risk_score_is_probability": False,
        "software_version": result.get("versions", {}).get("software"),
        "config_version": result.get("versions", {}).get("config"),
        "evidence_digest": hashlib.sha256(_canonical(evidence_summary)).hexdigest(),
        "models": model_attestations,
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    secret = os.getenv("RECEIPT_SIGNING_KEY", "").encode("utf-8")
    receipt = {**payload, "receipt_digest": digest, "integrity_mode": "HMAC_SHA256" if secret else "SHA256_DIGEST_ONLY"}
    if secret:
        receipt["signature"] = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
    return receipt


def verify_digest(receipt: dict[str, Any]) -> bool:
    """Verify digest-only integrity. HMAC verification remains server-side."""
    expected = receipt.get("receipt_digest")
    payload = {key: value for key, value in receipt.items() if key not in {"receipt_digest", "integrity_mode", "signature"}}
    return isinstance(expected, str) and hmac.compare_digest(expected, hashlib.sha256(_canonical(payload)).hexdigest())
