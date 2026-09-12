import cv2
from core.result_schema import EvidenceResult,DetectorStatus
class FaceQuality:
    name="face_quality"
    def analyse(self, context):
        faces=context.metadata.get("faces",[])
        if not faces:return [EvidenceResult(self.name,"face_quality",DetectorStatus.NOT_APPLICABLE,details={"reason":"No detected face"})]
        if len(faces) != 1:
            return [EvidenceResult(self.name,"face_quality",DetectorStatus.INCONCLUSIVE,value={"face_count":len(faces)},details={"reason":"Exactly one document portrait is required for reliable matching"},dependencies=["face_yunet"])]
        x,y,w,h=faces[0]["box"]; image_h,image_w=context.preprocessed.shape[:2]
        left,top,right,bottom=max(0,x),max(0,y),min(image_w,x+w),min(image_h,y+h)
        crop=context.preprocessed[top:bottom,left:right]
        if crop.size==0:return [EvidenceResult(self.name,"face_quality",DetectorStatus.INCONCLUSIVE,details={"reason":"Face crop outside image"},dependencies=["face_yunet"])]
        crop_w,crop_h=right-left,bottom-top; completeness=(crop_w*crop_h)/max(1,w*h)
        gray=cv2.cvtColor(crop,cv2.COLOR_RGB2GRAY); sharp=float(cv2.Laplacian(gray,cv2.CV_64F).var()); brightness=float(gray.mean()); contrast=float(gray.std())
        usable=crop_w>=80 and crop_h>=80 and completeness>=.9 and sharp>=35 and 35<=brightness<=225 and contrast>=18
        context.metadata["face_quality"]={"usable":usable,"face_count":1,"resolution":[crop_w,crop_h],"sharpness":round(sharp,2),"brightness":round(brightness,2),"contrast":round(contrast,2),"crop_completeness":round(completeness,3)}
        return [EvidenceResult(self.name,"face_crop_usable",DetectorStatus.NOT_DETECTED if usable else DetectorStatus.INCONCLUSIVE,value=context.metadata["face_quality"],reliability=.8,confidence=.85 if usable else .6,dependencies=["face_yunet"],details={"reason":None if usable else "Portrait failed size, blur, brightness, contrast, or crop-completeness gate"})]
