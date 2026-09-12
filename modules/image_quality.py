from __future__ import annotations
import cv2
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult

class ImageQuality(Detector):
    name="image_quality"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        im=context.preprocessed
        if im is None: return [EvidenceResult(self.name,"quality",DetectorStatus.ERROR,error_category="NO_IMAGE")]
        g=cv2.cvtColor(im,cv2.COLOR_RGB2GRAY); blur=float(cv2.Laplacian(g,cv2.CV_64F).var()); bright=float(g.mean()); contrast=float(g.std()); h,w=g.shape
        q=context.config["quality"]; failures=sum([w<q["min_width"],h<q["min_height"],blur<q["blur_variance_min"],bright<q["brightness_min"] or bright>q["brightness_max"],contrast<q["contrast_min"]])
        state="ANALYSABLE" if failures==0 else "PARTIALLY_ANALYSABLE" if failures<q["hard_failure_count"] else "INSUFFICIENT_QUALITY"
        context.metadata["quality"]={"status":state,"blur_variance":round(blur,2),"brightness":round(bright,2),"contrast":round(contrast,2),"resolution":[w,h],"gate_applied":state=="INSUFFICIENT_QUALITY"}
        status=DetectorStatus.DETECTED if state=="INSUFFICIENT_QUALITY" else DetectorStatus.NOT_DETECTED
        return [EvidenceResult(self.name,"insufficient_quality",status,value=context.metadata["quality"],reliability=.9,confidence=min(1,failures/3),severity=10 if failures else 0,dependencies=["image_quality"])]
