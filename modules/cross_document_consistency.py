from modules.field_normalizer import normalize_id, normalize_text
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class CrossDocumentConsistency(Detector):
    name = "cross_document_consistency"

    def __init__(self, repository=None):
        self.repository = repository

    @staticmethod
    def _normalise(name, value):
        return normalize_id(value, "aadhaar") if name in {"id_number", "phone"} else normalize_text(value)

    def analyse(self, context):
        identity_key = context.submission.get("identity_key")
        if not identity_key or self.repository is None:
            return [EvidenceResult(self.name, "cross_document_check", DetectorStatus.NOT_APPLICABLE, details={"reason": "A caller identity key and persisted history are required for cross-document comparison"})]
        current = {field.name: self._normalise(field.name, field.normalized_value or field.value) for field in context.fields if field.value}
        if not current:
            return [EvidenceResult(self.name, "cross_document_check", DetectorStatus.INCONCLUSIVE, details={"reason": "No reliable identity fields extracted from current document"}, dependencies=["ocr"])]
        prior = self.repository.identity_field_history(identity_key)
        contradictions = []
        comparable = {"name", "date_of_birth", "address", "phone", "id_number", "gender"}
        for record in prior:
            for name in comparable.intersection(current).intersection(record["fields"]):
                previous = self._normalise(name, record["fields"][name])
                if previous and current[name] and previous != current[name]:
                    contradictions.append({"field": name, "prior_screening_id": record["screening_id"]})
        value = {"prior_documents": len(prior), "compared_fields": sorted(current.keys()), "contradictions": contradictions[:10]}
        if contradictions:
            return [EvidenceResult(self.name, "cross_document_field_contradiction", DetectorStatus.DETECTED, value=value, reliability=.78, confidence=min(.95, .55 + .08 * len(contradictions)), severity=24, dependencies=["identity_history"], details={"reason": "A normalized identity field differs from prior documents submitted under the same identity key"})]
        return [EvidenceResult(self.name, "cross_document_consistent", DetectorStatus.NOT_DETECTED, value=value, reliability=.7 if prior else .35, confidence=.8 if prior else .4, dependencies=["identity_history"])]
