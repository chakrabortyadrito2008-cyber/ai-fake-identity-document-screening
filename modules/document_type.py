from __future__ import annotations
import re
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult

class DocumentTypeDetector(Detector):
    name="document_type"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        text=context.metadata.get("ocr",{}).get("raw_text","").upper(); scores={}
        aadhaar_brand=any(marker in text for marker in ("AADHAAR","AADHAR","UIDAI"))
        aadhaar_support=sum(marker in text for marker in ("GOVERNMENT OF INDIA","GOVERNMENT","BHARAT SARKAR","DATE OF BIRTH","PROOF OF IDENTITY"))
        aadhaar_number=bool(re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b",text))
        rules={"PAN":["INCOME TAX",r"\b[A-Z]{5}\d{4}[A-Z]\b"],"PASSPORT":["PASSPORT",r"\b[A-Z]\d{7}\b"],"VOTER_ID":["ELECTION COMMISSION",r"\b[A-Z]{3}\d{7}\b"],"DRIVING_LICENCE":["DRIVING LICENCE","DRIVING LICENSE",r"\b[A-Z]{2}\d{2}\s?\d{11,13}\b"]}
        scores["AADHAAR"]=(1 if aadhaar_brand else 0)+aadhaar_support+(1 if aadhaar_number else 0)
        for typ,patterns in rules.items(): scores[typ]=sum(1 for p in patterns if re.search(p,text))
        best=max(scores,key=scores.get,default="UNKNOWN"); top=scores[best]
        aadhaar_confirmed=aadhaar_brand and (aadhaar_support >= 1 or aadhaar_number)
        typ="AADHAAR" if aadhaar_confirmed else (best if top>=2 else "UNKNOWN")
        conf=min(.95,top/4) if typ!="UNKNOWN" else .2
        context.metadata["document_type"]={"value":typ,"confidence":conf,"candidate_types":scores,"reasons":"combined OCR keyword and pattern evidence"}
        return [EvidenceResult(self.name,"document_type",DetectorStatus.NOT_DETECTED,value=context.metadata["document_type"],reliability=.65,confidence=conf,dependencies=["ocr"])]
