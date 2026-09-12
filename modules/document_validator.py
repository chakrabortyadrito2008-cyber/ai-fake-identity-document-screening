from __future__ import annotations
import re
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class DocumentValidator(Detector):
    name="document_validator"
    def analyse(self, context):
        signals=[]; doc_type=context.metadata.get("document_type",{}).get("value","UNKNOWN")
        family_patterns={"AADHAAR":r"\d{12}","PAN":r"[A-Z]{5}\d{4}[A-Z]","PASSPORT":r"[A-Z]\d{7}"}
        for f in context.fields:
            if f.name=="id_number":
                pattern=family_patterns.get(doc_type)
                if pattern is None:
                    f.validation_status="INCONCLUSIVE_DOCUMENT_TYPE"; continue
                valid=bool(re.fullmatch(pattern,f.normalized_value)); f.validation_status="FORMAT_VALID" if valid else "FORMAT_INVALID"
                if not valid: signals.append(EvidenceResult(self.name,"id_format_invalid",DetectorStatus.DETECTED,reliability=.8,confidence=.8,severity=20,dependencies=["ocr"],details={"semantic":"format only, not identity authentication"}))
        return signals or [EvidenceResult(self.name,"format_validation",DetectorStatus.NOT_DETECTED,value="No invalid extracted format",dependencies=["ocr"])]
