from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class ArtifactIntelligence(Detector):
    name = "artifact_intelligence"

    def __init__(self, repository):
        self.repository = repository

    def analyse(self, context):
        p = context.metadata.get("provenance", {})
        state = "NEW" if not p.get("first_seen") else "NEUTRAL"
        fp = context.metadata.get("fingerprint", {}).get("phash")
        own_sha = context.metadata.get("fingerprint", {}).get("sha256")
        similar = self.repository.similar_phashes(fp, context.config["phash_distance_threshold"]) if fp else []
        # Exclude this artifact's own hash (exact matches are Provenance's job;
        # here we surface visually similar artifacts — potential duplicates).
        similar = [r for r in similar if r["sha256"] != own_sha]
        # Reference-registry documents are the organisation's known corpus:
        # matching them is positive evidence (handled by provenance), never a
        # duplicate suspicion.
        is_reference = getattr(self.repository, "is_reference", None)
        if is_reference:
            similar = [r for r in similar if not is_reference(r["sha256"])]
        # Near-duplicates at the strict threshold are genuinely suspicious:
        # the same document re-used with invisible pixel-level tampering.
        near = [r for r in similar if (int(fp, 16) ^ int(r["phash"], 16)).bit_count() <= context.config.get("near_duplicate_phash_threshold", 4)] if fp else []
        # A near-twin already on file under THIS identity is a benign re-scan
        # of their own document; suppress the cluster signal for it.
        identity = context.submission.get("identity_key")
        near = [r for r in near if not (identity and self.repository.history(r["sha256"])
            and identity in (self.repository.history(r["sha256"]).get("identities") or []))]
        # A reference-database match already corroborates this document.
        reference_matched = bool(context.metadata.get("reference_match"))
        context.metadata["similar_artifacts"] = [{"sha256": r["sha256"], "phash_distance": (int(fp, 16) ^ int(r["phash"], 16)).bit_count()} for r in similar[:10]]
        if near and not reference_matched:
            return [EvidenceResult(
                self.name, "near_duplicate_cluster", DetectorStatus.DETECTED,
                value={"near_duplicates": len(near), "related_sha256": [r["sha256"] for r in near[:5]]},
                reliability=.85, confidence=.85, severity=25, dependencies=["artifact_phash"],
                details={"reason": "Visually near-identical documents exist in the database; invisible pixel-level differences can indicate tampered reuse."},
            )]
        if reference_matched:
            state = "MATCHED_REFERENCE"
        return [EvidenceResult(
            self.name, "template_reputation", DetectorStatus.NOT_DETECTED,
            value={"reputation": state, "similar_artifacts": len(similar)},
            reliability=.4, confidence=.5, dependencies=["artifact_phash"],
            details={"similarity_is_not_identity": True, "index_note": "bounded SQLite fallback"},
        )]
