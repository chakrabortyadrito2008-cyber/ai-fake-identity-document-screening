from pathlib import Path
import cv2
import numpy as np
from core.result_schema import EvidenceResult,DetectorStatus
from modules.model_manager import ModelManager
class FaceDocumentMatch:
    name="face_document_match"
    def analyse(self, context):
        model=ModelManager(context.config,context.config.get("_root",".")).configured_models().get("sface",{})
        reference=context.submission.get("reference_face_path")
        if not context.config["features"].get("face_match") or not model.get("available"):
            return [EvidenceResult(self.name,"face_match",DetectorStatus.UNAVAILABLE,details={"reason":"SFace model missing or integrity check failed","model":model})]
        if not reference:return [EvidenceResult(self.name,"face_match",DetectorStatus.NOT_APPLICABLE,details={"reason":"No trusted reference face supplied"})]
        if not context.metadata.get("face_quality",{}).get("usable") or not context.metadata.get("yunet_faces"):
            return [EvidenceResult(self.name,"face_match",DetectorStatus.INCONCLUSIVE,details={"reason":"Document portrait did not pass face quality/detection gate"},dependencies=["face_yunet"])]
        reference_path=Path(reference)
        if not reference_path.is_file():return [EvidenceResult(self.name,"face_match",DetectorStatus.ERROR,error_category="REFERENCE_FACE_NOT_FOUND")]
        try:
            ref_bgr=cv2.imread(str(reference_path));
            if ref_bgr is None:return [EvidenceResult(self.name,"face_match",DetectorStatus.ERROR,error_category="REFERENCE_FACE_INVALID")]
            detector_model=ModelManager(context.config,context.config.get("_root",".")).configured_models()["yunet"]
            detector=cv2.FaceDetectorYN.create(detector_model["resolved_path"],"",(ref_bgr.shape[1],ref_bgr.shape[0]),.85,.3,20); _,reference_faces=detector.detect(ref_bgr)
            if reference_faces is None:return [EvidenceResult(self.name,"face_match",DetectorStatus.INCONCLUSIVE,details={"reason":"No usable face in reference image"},dependencies=["face_yunet"])]
            recognizer=cv2.FaceRecognizerSF.create(model["resolved_path"],"")
            document_bgr=cv2.cvtColor(context.preprocessed,cv2.COLOR_RGB2BGR)
            document_aligned=recognizer.alignCrop(document_bgr,np.asarray(context.metadata["yunet_faces"][0],dtype=np.float32))
            reference_aligned=recognizer.alignCrop(ref_bgr,reference_faces[0])
            document_feature=recognizer.feature(document_aligned); reference_feature=recognizer.feature(reference_aligned)
            similarity=float(recognizer.match(document_feature,reference_feature,cv2.FaceRecognizerSF_FR_COSINE)); threshold=float(context.config["face_matching"]["cosine_match_threshold"])
            result="MATCH" if similarity>=threshold else "MISMATCH"; context.metadata["face_match"]={"result":result,"similarity":round(similarity,4),"threshold":threshold}
            return [EvidenceResult(self.name,"face_mismatch" if result=="MISMATCH" else "face_match",DetectorStatus.DETECTED if result=="MISMATCH" else DetectorStatus.NOT_DETECTED,value=context.metadata["face_match"],reliability=.7,confidence=min(1.0,abs(similarity-threshold)+.5),severity=28 if result=="MISMATCH" else 0,dependencies=["face_yunet","sface"],details={"model":model["version"],"limitation":"Similarity is screening evidence, not legal identity authentication."})]
        except Exception as exc:return [EvidenceResult(self.name,"face_match",DetectorStatus.ERROR,error_category=type(exc).__name__)]
