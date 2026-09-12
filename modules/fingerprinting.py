from __future__ import annotations
import hashlib
import imagehash
from PIL import Image
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult
class Fingerprinting(Detector):
    name="fingerprinting"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        sha=hashlib.sha256(context.path.read_bytes()).hexdigest()
        original=Image.fromarray(context.preprocessed) if context.path.suffix.lower()==".pdf" else Image.open(context.path).convert("RGB")
        phash=str(imagehash.phash(original)); processed=Image.fromarray(context.preprocessed) if context.preprocessed is not None else original
        context.metadata["fingerprint"]={"sha256":sha,"phash":phash,"preprocessed_phash":str(imagehash.phash(processed))}
        return [EvidenceResult(self.name,"fingerprints_created",DetectorStatus.NOT_DETECTED,value=context.metadata["fingerprint"],reliability=1,confidence=1)]
