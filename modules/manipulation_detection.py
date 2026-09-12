import cv2
import numpy as np
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class ManipulationDetection(Detector):
    name = "manipulation_detection"

    def analyse(self, context):
        if context.preprocessed is None:
            return [EvidenceResult(self.name, "region_tampering", DetectorStatus.INCONCLUSIVE, details={"reason": "No analysable image"})]
        gray = cv2.cvtColor(context.preprocessed, cv2.COLOR_RGB2GRAY)
        height, width = gray.shape
        # Compare local residual-noise variation over a grid. A pasted or
        # strongly denoised region can differ from its surroundings; the
        # resulting candidates are review hints, never a proof of editing.
        blurred = cv2.GaussianBlur(gray, (3, 3), 0)
        residual = cv2.absdiff(gray, blurred).astype(np.float32)
        cell_h, cell_w = max(32, height // 8), max(32, width // 8)
        values, boxes = [], []
        for y in range(0, height - cell_h + 1, cell_h):
            for x in range(0, width - cell_w + 1, cell_w):
                values.append(float(residual[y:y+cell_h, x:x+cell_w].std())); boxes.append([x, y, cell_w, cell_h])
        if len(values) < 4:
            return [EvidenceResult(self.name, "region_tampering", DetectorStatus.INCONCLUSIVE, details={"reason": "Image is too small for regional consistency analysis"}, dependencies=["image_forensics"])]
        median=float(np.median(values)); mad=float(np.median(np.abs(np.asarray(values)-median)))
        threshold=median+max(.8, 4.0*mad)
        candidates=[box for value,box in zip(values,boxes) if value>threshold][:8]
        value={"grid_cells":len(values),"median_noise_variation":round(median,3),"candidate_regions":candidates,"candidate_count":len(candidates)}
        return [EvidenceResult(self.name,"inconsistent_image_regions" if candidates else "region_consistency",DetectorStatus.DETECTED if candidates else DetectorStatus.NOT_DETECTED,value=value,reliability=.45,confidence=.58 if candidates else .55,severity=14 if candidates else 0,dependencies=["image_forensics"],details={"limitation":"Regional noise inconsistency is a forensic review signal and can arise from benign capture or compression."})]
