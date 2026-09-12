import cv2
import numpy as np
import onnxruntime as ort
from functools import lru_cache
from core.result_schema import EvidenceResult,DetectorStatus
from modules.model_manager import ModelManager


@lru_cache(maxsize=2)
def _session(model_path: str):
    return ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
class LivenessDetection:
    name="liveness_detection"
    def analyse(self, context):
        model=ModelManager(context.config,context.config.get("_root",".")).configured_models().get("minifasnet_v2",{})
        if not context.config["features"].get("liveness") or not model.get("available"):
            return [EvidenceResult(self.name,"liveness",DetectorStatus.UNAVAILABLE,details={"reason":"MiniFASNetV2 model missing or integrity check failed","model":model})]
        # A portrait printed inside an identity document is not a live capture.
        # Running PAD on it produces predictable false positives. This detector
        # uses only the separately supplied still selfie; video liveness is not
        # implemented and is never claimed by this result.
        if not context.submission.get("live_selfie_path"):
            return [EvidenceResult(self.name,"liveness",DetectorStatus.NOT_APPLICABLE,details={"reason":"Liveness/PAD requires a separately captured still selfie; it is not valid on a portrait printed in a document. Video liveness is unavailable.","model":model.get("version")})]
        try:
            live_bgr=cv2.imread(str(context.submission["live_selfie_path"]))
            if live_bgr is None:
                return [EvidenceResult(self.name,"liveness",DetectorStatus.ERROR,error_category="LIVE_SELFIE_INVALID")]
            detector_model=ModelManager(context.config,context.config.get("_root",".")).configured_models().get("yunet", {})
            if not detector_model.get("available"):
                return [EvidenceResult(self.name,"liveness",DetectorStatus.UNAVAILABLE,details={"reason":"YuNet is required to crop the separate live selfie","model":detector_model})]
            detector=cv2.FaceDetectorYN.create(detector_model["resolved_path"],"",(live_bgr.shape[1],live_bgr.shape[0]),.85,.3,20)
            _, live_faces=detector.detect(live_bgr)
            if live_faces is None or len(live_faces) != 1:
                return [EvidenceResult(self.name,"liveness",DetectorStatus.INCONCLUSIVE,details={"reason":"Separate live selfie must contain exactly one detectable face"},dependencies=["face_yunet"])]
            x,y,w,h=map(int,live_faces[0][:4]); crop=live_bgr[max(0,y):min(live_bgr.shape[0],y+h),max(0,x):min(live_bgr.shape[1],x+w)]
            if crop.shape[0] < 80 or crop.shape[1] < 80:
                return [EvidenceResult(self.name,"liveness",DetectorStatus.INCONCLUSIVE,details={"reason":"Live-selfie face crop is too small for PAD"},dependencies=["face_yunet"])]
            gray=cv2.cvtColor(crop,cv2.COLOR_BGR2GRAY)
            if cv2.Laplacian(gray,cv2.CV_64F).var() < 35 or gray.mean() < 35 or gray.mean() > 225:
                return [EvidenceResult(self.name,"liveness",DetectorStatus.INCONCLUSIVE,details={"reason":"Live-selfie face crop failed blur or brightness quality gate"},dependencies=["face_yunet"])]
            bgr=cv2.resize(crop,(80,80)).astype(np.float32)
            tensor=np.transpose((bgr-127.5)/128.0,(2,0,1))[None,...]
            session=_session(model["resolved_path"])
            logits=session.run(None,{session.get_inputs()[0].name:tensor})[0][0]
            probabilities=np.exp(logits-logits.max()); probabilities=probabilities/probabilities.sum()
            labels=("LIVE","PRINT_ATTACK","REPLAY_ATTACK"); index=int(np.argmax(probabilities)); label=labels[index]
            context.metadata["liveness"]={"classification":label,"probabilities":{name:round(float(value),4) for name,value in zip(labels,probabilities)}}
            return [EvidenceResult(self.name,"presentation_attack" if label!="LIVE" else "liveness_completed",DetectorStatus.DETECTED if label!="LIVE" else DetectorStatus.NOT_DETECTED,value=context.metadata["liveness"],reliability=.65,confidence=float(probabilities[index]),severity=32 if label!="LIVE" else 0,dependencies=["face_yunet","minifasnet_v2"],details={"model":model["version"],"limitation":"Single-image PAD is supporting evidence, not proof of liveness."})]
        except Exception as exc:return [EvidenceResult(self.name,"liveness",DetectorStatus.ERROR,error_category=type(exc).__name__)]
