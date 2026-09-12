"""Local ONNX deepfake-image screening, used as supporting evidence only."""
import cv2
import numpy as np
import onnxruntime as ort
from functools import lru_cache

from core.result_schema import EvidenceResult, DetectorStatus
from modules.model_manager import ModelManager


@lru_cache(maxsize=2)
def _session(model_path: str):
    """Reuse the large ONNX runtime session across a folder/batch run."""
    return ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])


class DeepfakeDetection:
    name = "deepfake_detection"

    def analyse(self, context):
        if context.submission.get("analysis_mode") == "fast":
            return [EvidenceResult(self.name, "deepfake_deferred", DetectorStatus.NOT_APPLICABLE, details={"reason": "Deferred in fast batch mode; run full analysis for deepfake screening."})]
        model = ModelManager(context.config, context.config.get("_root", ".")).configured_models().get("deepfake_detector_v1", {})
        if not context.config["features"].get("deepfake") or not model.get("available"):
            return [EvidenceResult(self.name, "deepfake", DetectorStatus.UNAVAILABLE, details={"reason": "Deepfake ONNX model missing or integrity check failed", "model": model})]
        if context.preprocessed is None:
            return [EvidenceResult(self.name, "deepfake", DetectorStatus.INCONCLUSIVE, details={"reason": "No analysable image"})]
        try:
            # Model-card preprocessing: RGB, rescale 1/255, mean/std 0.5.
            rgb = cv2.resize(context.preprocessed, (224, 224), interpolation=cv2.INTER_AREA).astype(np.float32)
            tensor = np.transpose((rgb / 255.0 - 0.5) / 0.5, (2, 0, 1))[None, ...]
            session = _session(model["resolved_path"])
            logits = np.asarray(session.run(None, {session.get_inputs()[0].name: tensor})[0])[0]
            probabilities = np.exp(logits - logits.max())
            probabilities = probabilities / probabilities.sum()
            fake_probability, real_probability = float(probabilities[0]), float(probabilities[1])
            result = {"fake_probability": round(fake_probability, 4), "real_probability": round(real_probability, 4), "threshold": 0.8}
            context.metadata["deepfake"] = result
            flagged = fake_probability >= 0.8
            return [EvidenceResult(
                self.name,
                "synthetic_or_deepfake_likelihood" if flagged else "deepfake_screen_completed",
                DetectorStatus.DETECTED if flagged else DetectorStatus.NOT_DETECTED,
                value=result,
                reliability=0.45,
                confidence=fake_probability if flagged else real_probability,
                severity=28 if flagged else 0,
                dependencies=["deepfake_detector_v1"],
                details={"model": model.get("version"), "limitation": "A single-image classifier is screening evidence only; it is not proof of a deepfake, tampering, or identity fraud."},
            )]
        except Exception as exc:
            return [EvidenceResult(self.name, "deepfake", DetectorStatus.ERROR, error_category=type(exc).__name__)]
