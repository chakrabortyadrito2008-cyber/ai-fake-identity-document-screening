from core.result_schema import EvidenceResult, DetectorStatus


class PresentationAttack:
    """Expose the PAD conclusion without duplicating liveness risk evidence."""
    name = "presentation_attack"

    def analyse(self, context):
        liveness = context.metadata.get("liveness")
        if not liveness:
            return [EvidenceResult(self.name, "presentation_attack", DetectorStatus.NOT_APPLICABLE, details={"reason": "No face/PAD result available"})]
        label = liveness.get("classification")
        return [EvidenceResult(
            self.name,
            "presentation_attack_assessment",
            DetectorStatus.DETECTED if label in {"PRINT_ATTACK", "REPLAY_ATTACK"} else DetectorStatus.NOT_DETECTED,
            value=liveness,
            reliability=0.0,
            confidence=max(liveness.get("probabilities", {}).values(), default=0.0),
            severity=0.0,
            dependencies=["minifasnet_v2"],
            details={"reason": "Mirrors the liveness/PAD result for explainability; risk is scored only once by liveness_detection."},
        )]
