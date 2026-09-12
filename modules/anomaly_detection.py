"""Calibrated statistical novelty detector for document-image features."""
import json
import math
from pathlib import Path

import cv2
import numpy as np

from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class AnomalyDetection(Detector):
    name = "anomaly_detection"

    def _baseline(self, context):
        raw = context.config.get("anomaly_baseline_path", "")
        path = Path(raw)
        if raw and not path.is_absolute(): path = Path(context.config.get("_root", ".")) / path
        try:
            baseline = json.loads(path.read_text(encoding="utf-8"))
            if len(baseline["feature_names"]) != len(baseline["mean"]) or len(baseline["mean"]) != len(baseline["std"]): raise ValueError("inconsistent feature dimensions")
            if any(float(value) <= 0 for value in baseline["std"]): raise ValueError("non-positive standard deviation")
            return baseline
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None

    def analyse(self, context):
        baseline = self._baseline(context)
        if not context.config["features"].get("document_anomaly") or baseline is None:
            return [EvidenceResult(self.name, "novelty_detection", DetectorStatus.UNAVAILABLE, details={"reason": "No valid local anomaly baseline configured"})]
        if context.preprocessed is None:
            return [EvidenceResult(self.name, "novelty_detection", DetectorStatus.INCONCLUSIVE, details={"reason": "No analysable image"})]
        gray = cv2.cvtColor(context.preprocessed, cv2.COLOR_RGB2GRAY)
        height, width = gray.shape
        observed = np.array([
            float(gray.mean() / 255.0),
            float(gray.std() / 128.0),
            float(math.log1p(cv2.Laplacian(gray, cv2.CV_64F).var())),
            float(cv2.Canny(gray, 80, 180).mean() / 255.0),
            float(width / height),
        ])
        mean = np.asarray(baseline["mean"], dtype=float)
        std = np.asarray(baseline["std"], dtype=float)
        z_scores = np.abs((observed - mean) / std)
        score = float(np.mean(np.minimum(z_scores, 10.0)))
        threshold = float(baseline["anomaly_threshold"])
        demo_only = baseline.get("mode") == "DEMO_ONLY"
        value = {"novelty_score": round(score, 3), "threshold": threshold, "baseline_version": baseline.get("baseline_version"), "demo_only": demo_only}
        context.metadata["document_anomaly"] = value
        detected = score >= threshold
        return [EvidenceResult(
            self.name, "document_feature_novelty" if detected else "document_feature_baseline_match",
            DetectorStatus.DETECTED if detected else DetectorStatus.NOT_DETECTED,
            value=value, reliability=.25 if demo_only else .55,
            confidence=min(1.0, score / threshold) if detected else max(0.0, 1.0 - score / threshold),
            severity=14 if detected else 0, dependencies=["document_anomaly_baseline"],
            details={"feature_names": baseline["feature_names"], "baseline_source": baseline.get("source"), "demo_only": demo_only, "limitation": "Novelty is not proof of fraud; calibrate separately for each document type and capture channel."},
        )]
