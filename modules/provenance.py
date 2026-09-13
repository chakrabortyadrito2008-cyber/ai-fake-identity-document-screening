from __future__ import annotations
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


def _hamming(a: str, b: str) -> int:
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except (ValueError, TypeError):
        return 64


class Provenance(Detector):
    name = "provenance"

    def __init__(self, repository, near_duplicate_threshold: int | None = None, reference_threshold: int | None = None):
        self.repository = repository
        self.near_duplicate_threshold = near_duplicate_threshold
        self.reference_threshold = reference_threshold

    def _registry_lookup(self, phash: str | None, threshold: int) -> list[dict]:
        """Perceptual match against the reference corpus (official documents)."""
        if not phash or threshold <= 0:
            return []
        try:
            rows = self.repository.reference_phashes(limit=5000)
        except AttributeError:
            return []
        return [r for r in rows if _hamming(phash, r["phash"]) <= threshold]

    def analyse(self, context):
        sha = context.metadata["fingerprint"]["sha256"]
        prior = self.repository.history(sha)
        identity = context.submission.get("identity_key")
        context.metadata["provenance"] = prior or {"first_seen": None, "appearances": 0, "identities": []}
        # Test/benchmark identities are namespace-scoped so repeated automated
        # regression runs do not masquerade as real cross-person reuse.
        internal = lambda value: isinstance(value, str) and value.startswith(("autotest:", "autotest-fast:", "benchmark:"))
        prior_identities = [value for value in (prior or {}).get("identities", []) if value != "UNKNOWN" and not internal(value)]

        # --- Reference corpus (organisation database) matching: Q1 ----------
        # A document registered in the official reference database is a known
        # document. Byte-exact or perceptual matches are POSITIVE evidence.
        ref_threshold = self.reference_threshold
        if ref_threshold is None:
            ref_threshold = context.config.get("reference_phash_threshold", 6)
        is_reference = getattr(self.repository, "is_reference", None)
        exact_reference = bool(prior and is_reference and is_reference(sha))
        perceptual_reference = []
        if not exact_reference:
            phash = context.metadata["fingerprint"].get("phash")
            perceptual_reference = self._registry_lookup(phash, ref_threshold)
        if exact_reference or perceptual_reference:
            context.metadata["reference_match"] = {
                "exact": exact_reference,
                "matches": [r["label"] for r in perceptual_reference[:5]] if perceptual_reference else [],
            }
            # A registered reference document never counts as cross-person
            # reuse: screening it again is legitimate verification, exactly
            # the point of holding it in the database.
            prior_identities = []
            return [EvidenceResult(
                self.name, "reference_database_match", DetectorStatus.NOT_DETECTED,
                value={"exact": exact_reference, "perceptual_matches": [r["label"] for r in perceptual_reference[:5]]},
                reliability=.95, confidence=.95, dependencies=["artifact_sha", "artifact_phash"],
                details={
                    "reason": "Document is registered in the organisation reference database; database matching corroborates the document.",
                    "matching_is_positive_evidence": True,
                },
            )]

        # --- Submission-history matching: Q2 --------------------------------
        if prior:
            trusted_match = bool(context.metadata.get("trusted_source_match"))
            if trusted_match and (not prior_identities or identity in prior_identities):
                # Record exists, single consistent identity, trusted source
                # confirms this key: a database match genuinely corroborates
                # the document, so it auto-classifies genuine with proof.
                return [EvidenceResult(
                    self.name, "artifact_history_verified", DetectorStatus.NOT_DETECTED,
                    value={"appearances": prior.get("appearances", 0) + 1, "verified_prior": True},
                    reliability=.95, confidence=.95, dependencies=["artifact_sha"],
                )]
            if not identity and prior_identities:
                # Same document bytes resubmitted WITHOUT an identity key.
                # Not reusing across identities, but silent resubmission is a
                # classic liveness/audit-integrity concern: declare fake.
                return [EvidenceResult(
                    self.name, "silent_artifact_resubmission", DetectorStatus.DETECTED,
                    value={"prior_identity_count": len(prior_identities)},
                    reliability=.95, confidence=.95, severity=70, dependencies=["artifact_sha"],
                    details={"reason": "This exact document was previously submitted under a different caller; resubmitting it without identity context is a reuse pattern."},
                )]
            if identity and identity not in prior_identities and prior_identities:
                # Same document bytes under a DIFFERENT identity key.
                return [EvidenceResult(
                    self.name, "exact_artifact_cross_identity_reuse", DetectorStatus.DETECTED,
                    value={"prior_identity_count": len(prior_identities)},
                    reliability=.98, confidence=.98, severity=75, dependencies=["artifact_sha"],
                )]

        # --- Near-duplicate handling: Q3 -------------------------------------
        threshold = self.near_duplicate_threshold
        if threshold is None:
            threshold = context.config.get("near_duplicate_phash_threshold", 4)
        phash = context.metadata["fingerprint"].get("phash")
        if phash and threshold and threshold > 0:
            similar = self.repository.similar_phashes(phash, threshold)
            # Exclude the exact artifact itself from near-duplicate results.
            similar = [r for r in similar if r["sha256"] != sha]
            if similar:
                # Benign case first: the near-duplicate stored artifact belongs
                # to THIS identity (a re-scan/re-encode of their own document).
                owned = False
                for record in similar:
                    prior_record = self.repository.history(record["sha256"])
                    if prior_record and identity in (prior_record.get("identities") or []):
                        owned = True
                        break
                # Tiny pixel differences (re-encode, resize, minor pixel edit)
                # are invisible to humans but detected here. With a different
                # claimed identity this is inherently ambiguous — a reviewer
                # must compare the two images side by side.
                if not owned and not prior_identities and identity:
                    context.metadata["near_duplicate_of"] = [r["sha256"] for r in similar]
                    return [EvidenceResult(
                        self.name, "near_duplicate_artifact", DetectorStatus.DETECTED,
                        value={"similar_artifacts": len(similar), "related_sha256": [r["sha256"] for r in similar[:5]]},
                        reliability=.9, confidence=.9, severity=25, dependencies=["artifact_phash"],
                        details={"reason": "A visually near-identical document exists in the database under a different identity; a reviewer should compare the two images directly."},
                    )]
        return [EvidenceResult(
            self.name, "artifact_history", DetectorStatus.NOT_DETECTED,
            value=context.metadata["provenance"], reliability=.9, confidence=.9, dependencies=["artifact_sha"],
        )]
