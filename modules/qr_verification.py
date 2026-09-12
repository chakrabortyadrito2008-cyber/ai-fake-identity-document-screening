import cv2
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class QRVerification(Detector):
    name="qr_verification"
    def analyse(self, context):
        if not context.config["features"]["qr"]:return [EvidenceResult(self.name,"qr",DetectorStatus.UNAVAILABLE)]
        data,_,_=cv2.QRCodeDetector().detectAndDecode(context.preprocessed)
        if data:
            normalized=data.upper().replace(" ","")
            ids=[f.normalized_value for f in context.fields if f.name=="id_number"]
            match=any(i in normalized for i in ids) if ids else None
            status=DetectorStatus.DETECTED if match is False else DetectorStatus.NOT_DETECTED
            return [EvidenceResult(self.name,"qr_content_mismatch" if match is False else "qr_decoded",status,value={"decoded":True,"content_match":match,"authenticated":False},reliability=.85,confidence=.85,severity=22 if match is False else 0,dependencies=["qr_content"],details={"authentication":"UNAVAILABLE without a supported signature format"})]
        return [EvidenceResult(self.name,"qr",DetectorStatus.NOT_DETECTED,value={"detected":False},reliability=.8,confidence=.8)]
