from __future__ import annotations
import shutil
import pytesseract
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult

class OCREngine(Detector):
    name="ocr_engine"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        if not context.config["features"]["ocr"]: return [EvidenceResult(self.name,"ocr",DetectorStatus.UNAVAILABLE,details={"reason":"disabled"})]
        try:
            if not shutil.which("tesseract") and not __import__("os").environ.get("TESSERACT_PATH"):
                return [EvidenceResult(self.name,"ocr",DetectorStatus.UNAVAILABLE,details={"reason":"Tesseract executable unavailable"})]
            path=__import__("os").environ.get("TESSERACT_PATH")
            if path: pytesseract.pytesseract.tesseract_cmd=path
            cfg=context.config["ocr"]; runs=[]
            variant_limit=context.config["processing"]["max_ocr_variants"]
            for psm in cfg["psm"][:variant_limit]:
                data=pytesseract.image_to_data(context.preprocessed,lang=cfg["languages"],config=f"--psm {psm}",output_type=pytesseract.Output.DICT)
                tokens=[{"text":t,"confidence":float(x) if str(x)!="-1" else 0,"box":[data["left"][i],data["top"][i],data["width"][i],data["height"][i]]} for i,(t,x) in enumerate(zip(data["text"],data["conf"])) if t.strip()]
                runs.append(tokens)
            if not runs: return [EvidenceResult(self.name,"ocr",DetectorStatus.ERROR,error_category="OCR_CONFIGURATION")]
            text=" ".join(t["text"] for t in runs[0]); confidence=sum(t["confidence"] for t in runs[0])/max(1,len(runs[0]))/100
            context.metadata["ocr"]={"raw_text":text,"tokens":runs[0],"confidence":round(confidence,3),"engine":str(pytesseract.get_tesseract_version()),"variant_count":len(runs),"disagreement":runs[0]!=runs[-1]}
            return [EvidenceResult(self.name,"ocr_completed",DetectorStatus.NOT_DETECTED,value={"token_count":len(runs[0]),"confidence":confidence},reliability=.8,confidence=confidence,dependencies=["ocr"])]
        except Exception as exc: return [EvidenceResult(self.name,"ocr",DetectorStatus.ERROR,error_category=type(exc).__name__)]
