from __future__ import annotations
import warnings
from PIL import Image, UnidentifiedImageError
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult

class InputValidator(Detector):
    name="input_validator"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        p=context.path; c=context.config
        try:
            if not p.is_file(): return [EvidenceResult(self.name,"file_exists",DetectorStatus.ERROR,error_category="FILE_NOT_FOUND")]
            if p.suffix.lower() not in c["supported_extensions"]: return [EvidenceResult(self.name,"extension_allowed",DetectorStatus.ERROR,error_category="UNSUPPORTED_EXTENSION")]
            if p.stat().st_size > c["max_file_bytes"]: return [EvidenceResult(self.name,"size_limit",DetectorStatus.ERROR,error_category="FILE_TOO_LARGE")]
            if p.suffix.lower() == ".pdf":
                try:
                    import fitz
                    document=fitz.open(p)
                    if document.needs_pass: return [EvidenceResult(self.name,"pdf_validation",DetectorStatus.ERROR,error_category="ENCRYPTED_PDF")]
                    page_count=document.page_count
                    if not 1<=page_count<=c["processing"]["max_pdf_pages"]: return [EvidenceResult(self.name,"pdf_page_limit",DetectorStatus.ERROR,error_category="PDF_PAGE_LIMIT")]
                    page_sizes=[(round(page.rect.width),round(page.rect.height)) for page in document]
                    document.close()
                    context.metadata.update({"format":"PDF","pdf_pages":page_count,"pdf_page_sizes":page_sizes,"bytes":p.stat().st_size})
                    return [EvidenceResult(self.name,"safe_pdf",DetectorStatus.NOT_DETECTED,value=context.metadata,reliability=1,confidence=1)]
                except (ImportError, RuntimeError, OSError, ValueError) as exc:
                    return [EvidenceResult(self.name,"safe_pdf",DetectorStatus.ERROR,error_category=type(exc).__name__)]
            with warnings.catch_warnings():
                warnings.simplefilter("error",Image.DecompressionBombWarning)
                with Image.open(p) as im:
                    im.verify()
                with Image.open(p) as im:
                    if im.format not in {"PNG","JPEG","WEBP"}: return [EvidenceResult(self.name,"mime_validation",DetectorStatus.ERROR,error_category="UNSUPPORTED_MIME")]
                    if im.width*im.height>c["max_pixels"]: return [EvidenceResult(self.name,"pixel_limit",DetectorStatus.ERROR,error_category="PIXEL_LIMIT")]
                    context.metadata.update({"format":im.format,"width":im.width,"height":im.height,"bytes":p.stat().st_size})
            return [EvidenceResult(self.name,"safe_image",DetectorStatus.NOT_DETECTED,value=context.metadata,reliability=1,confidence=1)]
        except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            return [EvidenceResult(self.name,"safe_image",DetectorStatus.ERROR,error_category=type(exc).__name__)]
