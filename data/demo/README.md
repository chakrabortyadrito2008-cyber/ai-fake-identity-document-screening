# SIH demonstration data

`approved_records_demo.json` is a deliberately fictional local registry. It is useful for demonstrating the trusted-source connector with `--identity-key demo-legitimate-001`; it is not an authority or a real identity database.

`document_anomaly_baseline.json` is a simulated statistical baseline that demonstrates the full anomaly-detection flow. Replace it before deployment with a baseline calibrated on consented legitimate documents, measured false-positive rates, and a documented approval process.

To replace the registry, use a UTF-8 JSON array of records with `identity_key`, `source`, `confidence`, `record_version`, and `demo_only: false`, then update `trusted_source_path` in `config/settings.json`.
