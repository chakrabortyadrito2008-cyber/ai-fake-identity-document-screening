# AI-Based Fake Identity & Document Screening System

An offline-first, evidence-based system for screening fake identities, altered documents, document reuse, presentation attacks, and synthetic imagery. It does **not** claim a document is genuine, fake, legally verified, or fraud-confirmed. Its only outcomes are `LOW RISK`, `REVIEW REQUIRED`, `HIGH RISK`, and `INSUFFICIENT EVIDENCE`; the numeric value is an uncalibrated risk score, not a fraud probability.

## What runs today

Secure PNG/JPEG/WEBP validation, EXIF-safe preprocessing, image-quality metrics, optional Tesseract OCR, conservative document classification, candidate field extraction/format checks, QR decoding (not QR authentication), SHA-256 and pHash, SQLite provenance, cross-identity exact-artifact detection, NetworkX artifact graphs, temporal history, dependency-aware evidence fusion, structured explanations, a CLI, and a FastAPI service.

Model-backed checks only run when their local weights are present and SHA-256 verified. The included face, liveness, deepfake and document-anomaly checks are active. The trusted-source and anomaly components currently use clearly labelled SIH demonstration data under `data/demo/`; replace these with approved records and a calibrated baseline before deployment. Missing capabilities never add risk merely because they are absent.

## Windows setup

```powershell
cd C:\path\to\fraud_detection
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Optional OCR: install Tesseract and set TESSERACT_PATH if it is not on PATH
Copy-Item .env.example .env
py main.py self-test
py main.py screen C:\images\document.jpg --identity-key applicant-001
py main.py serve --host 127.0.0.1 --port 8000
```

API docs: `http://127.0.0.1:8000/docs`. Useful endpoints are `/screen`, `/screen/batch`, `/screen/{screening_id}`, `/screen/{screening_id}/receipt`, `/health`, `/capabilities`, `/models`, `/history/{sha}`, `/identity/{id}`, and `/artifact/{sha}`.

Open `http://127.0.0.1:8000/` for the browser dashboard. It supports selecting multiple document images or a folder (Chrome/Edge), sends them for batch screening, shows the triage label, and records every successful document in provenance. Batch uploads default to fast triage, which defers the CPU-heavy deepfake model; use full analysis only for priority files. For offline folder ingestion use: `py main.py screen-folder C:\documents --identity-key-prefix batch-001`. Add `--full-deepfake` to run deepfake inference for every file, or `--limit 25` for a controlled test. The source folder is never modified; an immutable batch report is written under `C:\documents\screening_reports\`.

The operational labels are `LIKELY GENUINE — NOT VERIFIED`, `NEEDS MANUAL VERIFICATION`, and `LIKELY FAKE / FRAUD SIGNALS`. Low-risk documents with no fraud signals are automatically classified as `LIKELY GENUINE`; manual verification is reserved only for documents whose genuineness cannot be determined (insufficient quality, conflicting evidence, or no clear decision). Any high-confidence fraud or presentation-attack signal is classified as `LIKELY FAKE`. These remain screening triage labels, not a legal declaration that a document is genuine or fake.

`POST /screen` accepts multipart form data: `file` and optional `identity_key`. Uploads are size-bounded, validated and deleted from an isolated temporary directory after processing. The API deliberately does not accept arbitrary server file paths; use the CLI for trusted local automation.

For `/screen/batch`, submit repeated `files`, an optional shared `identity_key`, or `identity_keys_json` as a JSON array aligned with the uploaded files. The response includes bounded same-batch exact-artifact correlations; each file remains independently screened and persisted.

To use a local organisation-approved trusted source, set `trusted_source_path` in `config/settings.json` to a UTF-8 JSON array of records keyed by `identity_key`. Synthetic fixture data is never loaded as a production trusted source by default.

## Models and operational notes

Put model metadata (name, version, SHA-256, licence, source and input semantics) under `models/manifests/`, then enable the related feature in `config/settings.json` only after integrity verification. Do not add a model merely because it is popular; assess performance, licence, platform support, false-negative/false-positive performance and maintenance first. SQLite runs in WAL mode with short transactional writes; replace the repository implementation for PostgreSQL deployment.

The CPU model stack includes integrity-verified YuNet face detection, SFace face embeddings, MiniFASNetV2 passive presentation-attack detection, and an ONNX SigLIP deepfake-image classifier. Face matching requires a separately supplied trusted reference face, for example: `py main.py screen C:\images\document.jpg --reference-face C:\images\reference.jpg`. MiniFASNetV2 is intentionally not run on a portrait printed within a document because that produces false print/replay alerts; it is reserved for a separate live-selfie/video capture flow. Face similarity and deepfake classification are screening evidence only; neither is legal identity authentication or proof that a document is fake. The deepfake alert threshold is deliberately conservative (0.80) and its contribution to the fused score is capped. Research-only DeepfakeBench/Effort is not bundled because it requires a separate benchmark stack, data and calibration.

For e-Aadhaar landscape images, an additional privacy-preserving layout profile checks expected aspect ratio, generic text-marker groups and portrait placement. The profile stores no personal data from the reference. It flags inconsistent templates for manual review but never treats a visual match as UIDAI authentication. UIDAI states that Aadhaar Secure QR codes are digitally signed and usable for offline identity verification; connect a supported signature verifier or use the official scanner for an authoritative QR check. 

Synthetic historical fixtures are in `data/synthetic_data/`. They are test data only and must never be treated as authoritative identity data.

## Test

```powershell
pytest -q
```

The app masks sensitive IDs, phones and addresses in returned extracted-field summaries. Raw OCR is retained only in transient analysis metadata and is not logged.

## Decision intelligence

Each result now contains a dependency-aware explanation, risk-driver shares, evidence-coverage counts and an actionable review playbook. This avoids the common “black-box score” problem: reviewers can see both the signals and the safest next verification action. An `analysis_receipt` binds the input fingerprint, configuration version, evidence digest and model hashes. Set `RECEIPT_SIGNING_KEY` in `.env` to make receipts HMAC-signed; without it, the receipt remains a deterministic integrity digest but does not establish server origin.

Retention cleanup is intentionally explicit rather than automatic: `py main.py purge-retention --days 365`. Review your organisation's retention policy before running it.

## Deployment

For a local deployment, run `py main.py serve --host 127.0.0.1 --port 8000` and open `http://127.0.0.1:8000/`. For Docker, install Docker Desktop and run `docker compose up --build -d` from this folder, then open `http://127.0.0.1:8000/`. Before exposing the service beyond a trusted network, enable `api.require_api_key`, set `FRAUD_API_KEY`, set `RECEIPT_SIGNING_KEY`, replace demo data, and put it behind HTTPS authentication.

The operations console includes a human review queue: Approve, Reject, or Escalate decisions are written separately from immutable screening evidence and are audit logged. Check `/operations/readiness` for the live external-deployment gate and see `docs/PRODUCTION_READINESS.md` for the full checklist.

## Dataset benchmarking

For a resumable local benchmark that persists every result in provenance and checkpoints a JSON report every ten files, run: `py tools\run_dataset_benchmark.py "C:\images"`. It defaults to fast triage; use `--mode full` only for a smaller validated subset because CPU deepfake inference is expensive. The report is written to `data\benchmarks\aadhaar_generated_benchmark.json` and can be safely resumed by running the same command again.
