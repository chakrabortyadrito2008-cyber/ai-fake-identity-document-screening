from __future__ import annotations
import re
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult, FieldValue
from modules.field_normalizer import normalize_id, normalize_text

class IdentityExtractor(Detector):
    name="identity_extractor"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        text=context.metadata.get("ocr",{}).get("raw_text",""); ocr_conf=context.metadata.get("ocr",{}).get("confidence",0)
        found=[]
        patterns={"aadhaar":r"\b\d{4}\s?\d{4}\s?\d{4}\b","pan":r"\b[A-Z]{5}\d{4}[A-Z]\b","passport":r"\b[A-Z]\d{7}\b","dob":r"\b(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}\b","phone":r"\b(?:\+91[- ]?)?[6-9]\d{9}\b"}
        for key,pat in patterns.items():
            for value in re.findall(pat,text,re.I): found.append(FieldValue("id_number" if key in {"aadhaar","pan","passport"} else key,value,normalize_id(value,key) if key in {"aadhaar","pan","passport"} else normalize_text(value),ocr_conf,source_region=key,ocr_confidence=ocr_conf))
        context.fields=found
        return [EvidenceResult(self.name,"identity_fields_extracted",DetectorStatus.NOT_DETECTED,value={"count":len(found),"types":[x.name for x in found]},reliability=.7,confidence=ocr_conf,dependencies=["ocr"])]
