from __future__ import annotations
import numpy as np
from PIL import Image, ImageEnhance, ImageOps
from core.analysis_engine import AnalysisContext, Detector
from core.result_schema import DetectorStatus, EvidenceResult

class Preprocessor(Detector):
    name="preprocessing"
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]:
        if context.path.suffix.lower()==".pdf":
            try:
                import fitz
                document=fitz.open(context.path); dpi=int(context.config["processing"]["pdf_render_dpi"]); scale=dpi/72
                rendered=[]
                for page in document:
                    pix=page.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
                    rendered.append(np.array(Image.frombytes("RGB",[pix.width,pix.height],pix.samples)))
                document.close()
                width=max(image.shape[1] for image in rendered); separator=np.full((16,width,3),255,dtype=np.uint8); pages=[]
                for image in rendered:
                    if image.shape[1]!=width:
                        image=np.array(Image.fromarray(image).resize((width,round(image.shape[0]*width/image.shape[1]))))
                    pages.extend((image,separator))
                combined=np.vstack(pages[:-1])
                if combined.shape[0]*combined.shape[1]>context.config["max_pixels"]:
                    ratio=(context.config["max_pixels"]/(combined.shape[0]*combined.shape[1]))**.5
                    combined=np.array(Image.fromarray(combined).resize((max(1,round(combined.shape[1]*ratio)),max(1,round(combined.shape[0]*ratio)))))
                image=Image.fromarray(combined)
                context.metadata["pdf_rendering"]={"pages_rendered":len(rendered),"dpi":dpi,"composited":len(rendered)>1}
            except (ImportError, RuntimeError, OSError, ValueError) as exc:
                return [EvidenceResult(self.name,"pdf_rendering",DetectorStatus.ERROR,error_category=type(exc).__name__)]
        else:
            image=Image.open(context.path).convert("RGB")
        original=np.array(image)
        image=ImageOps.exif_transpose(image)
        image=ImageEnhance.Contrast(image).enhance(1.15)
        image=ImageEnhance.Brightness(image).enhance(1.03)
        context.image=original; context.preprocessed=np.array(image)
        context.metadata["preprocessing"]={"exif_oriented":True,"contrast":1.15,"brightness":1.03,"original_preserved":True,"pdf_pages":context.metadata.get("pdf_pages",1)}
        return [EvidenceResult(self.name,"preprocessed",DetectorStatus.NOT_DETECTED,value=context.metadata["preprocessing"],reliability=1,confidence=1)]
