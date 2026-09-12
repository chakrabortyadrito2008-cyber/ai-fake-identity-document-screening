import cv2
from core.result_schema import EvidenceResult,DetectorStatus
from modules.model_manager import ModelManager
class FaceDetection:
    name="face_detection"
    def analyse(self, context):
        model=ModelManager(context.config, context.config.get("_root", ".")).configured_models().get("yunet",{})
        if not context.config["features"].get("face_detection") or not model or not model["available"]:
            return [EvidenceResult(self.name,"face_detection",DetectorStatus.UNAVAILABLE,details={"reason":"YuNet model missing, unverified, or not licence-approved","model":model})]
        try:
            image=context.preprocessed
            bgr=cv2.cvtColor(image,cv2.COLOR_RGB2BGR); h,w=bgr.shape[:2]
            detector=cv2.FaceDetectorYN.create(model["resolved_path"],"",(w,h),.85,.3,20)
            _,faces=detector.detect(bgr)
            if faces is None or len(faces)==0:return [EvidenceResult(self.name,"face_presence",DetectorStatus.NOT_DETECTED,value={"count":0},reliability=.9,confidence=.9,dependencies=["face_yunet"],details={"model":model["version"]})]
            found=[]; raw_faces=[]
            for face in faces:
                x,y,fw,fh,confidence=face[:5]; found.append({"box":[int(x),int(y),int(fw),int(fh)],"confidence":float(confidence)}); raw_faces.append(face.astype(float).tolist())
            context.metadata["faces"]=found
            context.metadata["yunet_faces"]=raw_faces
            return [EvidenceResult(self.name,"face_presence",DetectorStatus.NOT_DETECTED,value={"count":len(found),"faces":found},reliability=.9,confidence=min(x["confidence"] for x in found),dependencies=["face_yunet"],details={"model":model["version"],"method":"OpenCV FaceDetectorYN / YuNet"})]
        except Exception as exc:
            return [EvidenceResult(self.name,"face_detection",DetectorStatus.ERROR,error_category=type(exc).__name__,details={"model":"YuNet"})]
