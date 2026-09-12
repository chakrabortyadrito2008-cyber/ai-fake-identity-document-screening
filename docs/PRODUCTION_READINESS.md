# External deployment readiness

The local application is a working human-in-the-loop screening system, not an externally deployable service by default. The `/operations/readiness` endpoint shows the live blockers.

Before a company deployment:

1. Set `FRAUD_ENVIRONMENT=production`, enable `api.require_api_key`, and set strong `FRAUD_API_KEY` and `RECEIPT_SIGNING_KEY` values in a secrets manager.
2. Replace `data/demo/approved_records_demo.json` with an approved, access-controlled trusted source. Keep demo data out of the deployed image.
3. Replace the demo anomaly baseline with a consented, labelled, document-type/capture-channel-specific evaluation and recorded thresholds.
4. Put the API behind TLS, authenticated gateway controls, request logging/monitoring, backups, and a tested incident-response plan.
5. Move from SQLite to a managed database before horizontally scaling the API; keep audit and review-decision retention policies documented.
6. Establish reviewer roles, least-privilege access, consent/privacy notices, retention/deletion procedures, model version change control, and an appeal/escalation process.
7. Measure false positives/negatives across the intended population and document types. Do not market or use the screening labels as proof of issuer authenticity.

The operational review queue keeps reviewer decisions separate from immutable input evidence and records an audit event for each resolution.
