SCHEMA_VERSION=1
DDL="""
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (sha256 TEXT PRIMARY KEY, phash TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, appearances INTEGER NOT NULL DEFAULT 0, template_reputation TEXT NOT NULL DEFAULT 'UNKNOWN');
CREATE TABLE IF NOT EXISTS reference_documents (sha256 TEXT PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS screenings (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, submitted_at TEXT NOT NULL, identity_key TEXT, outcome TEXT NOT NULL, risk_score REAL NOT NULL, result_json TEXT NOT NULL, FOREIGN KEY(sha256) REFERENCES artifacts(sha256));
CREATE INDEX IF NOT EXISTS idx_screenings_sha ON screenings(sha256);
CREATE INDEX IF NOT EXISTS idx_screenings_identity ON screenings(identity_key);
CREATE INDEX IF NOT EXISTS idx_screenings_time ON screenings(submitted_at);
CREATE TABLE IF NOT EXISTS artifact_identities (sha256 TEXT NOT NULL, identity_key TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY(sha256,identity_key));
CREATE TABLE IF NOT EXISTS evidence_snapshots (screening_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_sha256 TEXT NOT NULL, config_version TEXT NOT NULL, snapshot_json TEXT NOT NULL, FOREIGN KEY(screening_id) REFERENCES screenings(id));
CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL, request_id TEXT, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS review_decisions (screening_id TEXT PRIMARY KEY, decision TEXT NOT NULL CHECK(decision IN ('APPROVED','REJECTED','ESCALATED')), reviewer_id TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL, FOREIGN KEY(screening_id) REFERENCES screenings(id));
CREATE INDEX IF NOT EXISTS idx_review_decisions_time ON review_decisions(decided_at);
"""
