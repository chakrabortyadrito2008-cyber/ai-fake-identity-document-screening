from __future__ import annotations
import json, uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from database.db_manager import DatabaseManager
from core.result_schema import utcnow

class ScreeningRepository:
    def __init__(self, db: DatabaseManager): self.db=db
    def history(self, sha: str) -> dict[str,Any] | None:
        with self.db.connection() as c:
            a=c.execute("SELECT * FROM artifacts WHERE sha256=?",(sha,)).fetchone()
            if not a:return None
            identities=[r[0] for r in c.execute("SELECT identity_key FROM artifact_identities WHERE sha256=?",(sha,))]
            return {**dict(a),"identities":identities}
    def record(self, sha: str, phash: str, identity_key: str | None, outcome: str, score: float, result: dict, screening_id: str | None=None) -> str:
        now=utcnow(); ident=identity_key or "UNKNOWN"; sid=screening_id or str(uuid.uuid4())
        with self.db.connection() as c:
            c.execute("INSERT INTO artifacts(sha256,phash,first_seen,last_seen,appearances) VALUES(?,?,?,?,1) ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen,appearances=artifacts.appearances+1",(sha,phash,now,now))
            c.execute("INSERT OR IGNORE INTO artifact_identities VALUES(?,?,?)",(sha,ident,now))
            c.execute("INSERT INTO screenings VALUES(?,?,?,?,?,?,?)",(sid,sha,now,identity_key,outcome,score,json.dumps(result)))
            c.execute("INSERT INTO evidence_snapshots(screening_id,created_at,input_sha256,config_version,snapshot_json) VALUES(?,?,?,?,?)",(sid,now,sha,result.get("versions",{}).get("config","unknown"),json.dumps(result)))
        return sid
    def identity_history(self, identity: str) -> list[dict]:
        with self.db.connection() as c:return [dict(r) for r in c.execute("SELECT id,sha256,submitted_at,outcome,risk_score FROM screenings WHERE identity_key=? ORDER BY submitted_at DESC",(identity,))]
    def identity_field_history(self, identity: str, limit: int = 50) -> list[dict]:
        """Return prior extracted fields for one caller-supplied identity key.

        SQLite stores the immutable screening result as JSON, so fields are
        decoded here instead of creating a second mutable copy of PII.
        """
        with self.db.connection() as c:
            rows = c.execute("SELECT id,sha256,submitted_at,result_json FROM screenings WHERE identity_key=? ORDER BY submitted_at DESC LIMIT ?", (identity, max(1, min(limit, 500)))).fetchall()
        records = []
        for row in rows:
            result = json.loads(row["result_json"])
            fields = {item.get("name"): item.get("normalized_value") for item in result.get("identity", {}).get("fields", []) if item.get("name") and item.get("normalized_value")}
            records.append({"screening_id": row["id"], "sha256": row["sha256"], "submitted_at": row["submitted_at"], "fields": fields})
        return records
    def recent_activity(self, identity_key: str | None, phash: str | None, seconds: int = 300) -> dict:
        """Privacy-minimised rate telemetry derived from persisted submissions."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(1, seconds))).isoformat()
        with self.db.connection() as c:
            identity_count = c.execute("SELECT COUNT(*) FROM screenings WHERE identity_key=? AND submitted_at>=?", (identity_key, cutoff)).fetchone()[0] if identity_key else 0
            phash_count = c.execute("SELECT COUNT(*) FROM screenings s JOIN artifacts a ON a.sha256=s.sha256 WHERE a.phash=? AND s.submitted_at>=?", (phash, cutoff)).fetchone()[0] if phash else 0
            total_count = c.execute("SELECT COUNT(*) FROM screenings WHERE submitted_at>=?", (cutoff,)).fetchone()[0]
        return {"window_seconds": seconds, "identity_submissions": identity_count, "visual_artifact_submissions": phash_count, "total_submissions": total_count}
    def graph_records(self, limit: int = 1000) -> list[dict]:
        """Load bounded, persisted artifact-to-identity/field relationships."""
        with self.db.connection() as c:
            rows = c.execute("SELECT id,sha256,identity_key,result_json FROM screenings ORDER BY submitted_at DESC LIMIT ?", (max(1, min(limit, 5000)),)).fetchall()
        records = []
        for row in rows:
            result = json.loads(row["result_json"])
            fields = {item.get("name"): item.get("normalized_value") for item in result.get("identity", {}).get("fields", []) if item.get("normalized_value")}
            records.append({"screening_id": row["id"], "sha256": row["sha256"], "identity_key": row["identity_key"], "fields": fields})
        return records
    def artifact(self, sha: str) -> dict | None: return self.history(sha)
    def screening(self, screening_id: str) -> dict | None:
        with self.db.connection() as c:
            row=c.execute("SELECT result_json FROM screenings WHERE id=?",(screening_id,)).fetchone()
            return json.loads(row["result_json"]) if row else None
    def screenings_page(self, verdict: str | None = None, limit: int = 100) -> dict:
        """Bounded newest-first listing of all screenings, optionally filtered by triage verdict."""
        limit = max(1, min(int(limit), 500))
        allowed = {"LIKELY_GENUINE", "LIKELY_FAKE", "MANUAL_VERIFICATION"}
        with self.db.connection() as c:
            counts = {row[0]: row[1] for row in c.execute("SELECT json_extract(result_json,'$.triage.code') AS code, COUNT(*) FROM screenings GROUP BY code")}
            if verdict in allowed:
                rows = c.execute("SELECT id, submitted_at, outcome, risk_score, result_json FROM screenings WHERE json_extract(result_json,'$.triage.code')=? ORDER BY submitted_at DESC LIMIT ?", (verdict, limit)).fetchall()
            else:
                rows = c.execute("SELECT id, submitted_at, outcome, risk_score, result_json FROM screenings ORDER BY submitted_at DESC LIMIT ?", (limit,)).fetchall()
        items = []
        for row in rows:
            result = json.loads(row["result_json"]); triage = result.get("triage", {})
            items.append({
                "screening_id": row["id"], "submitted_at": row["submitted_at"],
                "filename": result.get("filename"),
                "triage": triage.get("label", row["outcome"]),
                "triage_code": triage.get("code", ""),
                "risk_score": row["risk_score"], "status": row["outcome"],
                "document_type": (result.get("document_type") or {}).get("value"),
                "reasons": [item.get("signal") for item in result.get("evidence", []) if item.get("status") == "DETECTED" and item.get("severity", 0) > 0][:3],
            })
        return {"counts": counts, "items": items}
    def review_queue(self, limit: int = 100, include_resolved: bool = False) -> list[dict]:
        """Return a bounded, privacy-minimised human-review work queue."""
        limit=max(1,min(int(limit),500))
        with self.db.connection() as c:
            rows=c.execute("""SELECT s.id,s.submitted_at,s.outcome,s.risk_score,s.result_json,
                r.decision,r.reviewer_id,r.notes,r.decided_at
                FROM screenings s LEFT JOIN review_decisions r ON r.screening_id=s.id
                ORDER BY s.submitted_at DESC LIMIT ?""",(500,)).fetchall()
        queue=[]
        for row in rows:
            result=json.loads(row["result_json"]); triage=result.get("triage",{})
            # Only undetermined (suspicious) documents await a human. Genuine and
            # fake are automatic declarations; reviewers may still override any
            # auto decision through record_review_decision (audit-trailed).
            code=triage.get("code")
            needs_human=code=="MANUAL_VERIFICATION" or (not triage and result.get("status") in {"REVIEW REQUIRED","INSUFFICIENT EVIDENCE"})
            if not needs_human or (row["decision"] and not include_resolved): continue
            related=[]
            for item in result.get("evidence", []):
                if item.get("status")=="DETECTED" and item.get("detector") in {"provenance","artifact_intelligence"}:
                    related.extend(item.get("value",{}).get("related_sha256",[]))
            queue.append({
                "screening_id":row["id"],"submitted_at":row["submitted_at"],"filename":result.get("filename"),
                "triage":triage.get("label",result.get("status")),"risk_score":result.get("risk_score"),
                "status":result.get("status"),"quality":result.get("quality",{}).get("status"),
                "related_artifacts":related[:5],
                "reasons":[item.get("signal") for item in result.get("evidence",[]) if item.get("status")=="DETECTED" and item.get("severity",0)>0][:4],
                "review":{"decision":row["decision"],"reviewer_id":row["reviewer_id"],"notes":row["notes"],"decided_at":row["decided_at"]} if row["decision"] else None,
            })
            if len(queue)>=limit: break
        return queue
    def record_review_decision(self, screening_id: str, decision: str, reviewer_id: str, notes: str, request_id: str | None=None) -> dict:
        if decision not in {"APPROVED","REJECTED","ESCALATED"}: raise ValueError("Invalid review decision")
        if not self.screening(screening_id): raise KeyError("Screening not found")
        decided_at=utcnow()
        with self.db.connection() as c:
            c.execute("""INSERT INTO review_decisions(screening_id,decision,reviewer_id,notes,decided_at)
                VALUES(?,?,?,?,?) ON CONFLICT(screening_id) DO UPDATE SET
                decision=excluded.decision,reviewer_id=excluded.reviewer_id,notes=excluded.notes,decided_at=excluded.decided_at""",
                (screening_id,decision,reviewer_id,notes,decided_at))
        self.audit("review_decision",request_id,{"screening_id":screening_id,"decision":decision,"reviewer_id":reviewer_id})
        return {"screening_id":screening_id,"decision":decision,"reviewer_id":reviewer_id,"notes":notes,"decided_at":decided_at}
    def operations_overview(self) -> dict:
        queue=self.review_queue(limit=500,include_resolved=False)
        with self.db.connection() as c:
            total=c.execute("SELECT COUNT(*) FROM screenings").fetchone()[0]
            decisions={row[0]:row[1] for row in c.execute("SELECT decision,COUNT(*) FROM review_decisions GROUP BY decision")}
        return {"total_screenings":total,"pending_review":len(queue),"recent_queue":queue[:8],"review_decisions":decisions,"database":"SQLite (local deployment)"}
    def similar_phashes(self, phash: str, max_distance: int, limit: int = 500) -> list[dict]:
        """Bounded SQLite fallback; replace with a perceptual-hash index at scale.

        Same-pHash rows are retained: visually identical images with different
        bytes (re-encodes, format changes) are exactly the near-duplicate
        evidence reviewers need; the caller filters out the current artifact.
        """
        with self.db.connection() as c:
            rows=[dict(r) for r in c.execute("SELECT sha256,phash,appearances,template_reputation FROM artifacts ORDER BY last_seen DESC LIMIT ?",(limit,))]
        def distance(a: str,b: str) -> int: return (int(a,16)^int(b,16)).bit_count()
        return [r for r in rows if distance(phash,r["phash"])<=max_distance]

    def reference_phashes(self, limit: int = 5000) -> list[dict]:
        """Reference-corpus fingerprints for perceptual database matching."""
        with self.db.connection() as c:
            rows=[dict(r) for r in c.execute("SELECT a.sha256,a.phash,r.label FROM reference_documents r JOIN artifacts a ON a.sha256=r.sha256 ORDER BY r.label LIMIT ?",(max(1,min(limit,5000)),))]
        return rows
    def register_reference(self, sha: str, phash: str, identity_key: str, label: str) -> None:
        """Register a reference-database document (idempotent per sha256).

        Reference entries live in the same artifacts table but carry
        `registry:`-prefixed identities and a KNOWN template reputation so
        detectors can distinguish an official corpus record from a prior
        screening submission.
        """
        now = utcnow()
        with self.db.connection() as c:
            c.execute("INSERT INTO artifacts(sha256,phash,first_seen,last_seen,appearances,template_reputation) VALUES(?,?,?,?,1,'KNOWN') ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen,phash=excluded.phash", (sha, phash, now, now))
            c.execute("INSERT OR IGNORE INTO artifact_identities VALUES(?,?,?)", (sha, identity_key, now))
            c.execute("INSERT OR IGNORE INTO reference_documents(sha256,label) VALUES(?,?)", (sha, label))

    def reference_count(self) -> int:
        with self.db.connection() as c:
            return c.execute("SELECT COUNT(*) FROM reference_documents").fetchone()[0]

    def is_reference(self, sha: str) -> bool:
        with self.db.connection() as c:
            return c.execute("SELECT 1 FROM reference_documents WHERE sha256=?", (sha,)).fetchone() is not None

    def audit(self, action: str, request_id: str | None, details: dict):
        with self.db.connection() as c:c.execute("INSERT INTO audit_events(timestamp,action,request_id,details) VALUES(?,?,?,?)",(utcnow(),action,request_id,json.dumps(details)))
    def purge_expired(self, retention_days: int) -> dict[str,int]:
        """Explicitly purge old screening snapshots; never invoked during screening."""
        cutoff=(datetime.now(timezone.utc)-timedelta(days=retention_days)).isoformat()
        with self.db.connection() as c:
            count=c.execute("SELECT COUNT(*) FROM screenings WHERE submitted_at < ?",(cutoff,)).fetchone()[0]
            if not count: return {"screenings":0,"artifacts":0}
            c.execute("DELETE FROM evidence_snapshots WHERE screening_id IN (SELECT id FROM screenings WHERE submitted_at < ?)",(cutoff,))
            c.execute("DELETE FROM screenings WHERE submitted_at < ?",(cutoff,))
            before=c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
            c.execute("DELETE FROM artifacts WHERE sha256 NOT IN (SELECT DISTINCT sha256 FROM screenings)")
            c.execute("DELETE FROM artifact_identities WHERE sha256 NOT IN (SELECT sha256 FROM artifacts)")
            return {"screenings":count,"artifacts":before-c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]}
