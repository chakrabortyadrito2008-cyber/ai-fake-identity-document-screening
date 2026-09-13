import io
import cv2, numpy as np
from PIL import Image, ImageChops
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult

# Metadata strings that reveal the image was produced by an editor or a
# generative model. Matching is deliberately case-insensitive and
# substring-based because vendors vary spacing and capitalisation.
_EDITING_SOFTWARE_MARKERS = ("photoshop", "gimp", "lightroom", "affinity photo",
                             "pixlr", "canva", "picsart", "snapseed", "facetune",
                             "paint.net", "corel paint", "photopea", "pixelmator")
_AI_GENERATOR_MARKERS = ("dall-e", "dall·e", "dalle", "midjourney", "stable diffusion",
                         "stablediffusion", "comfyui", "automatic1111", "invokeai",
                         "firefly", "imagen", "gan", "diffusion model", "generative")
class Forensics(Detector):
    name="forensics"
    def analyse(self, context):
        if not context.config["features"]["forensics"]:return [EvidenceResult(self.name,"forensics",DetectorStatus.UNAVAILABLE)]
        gray=cv2.cvtColor(context.preprocessed,cv2.COLOR_RGB2GRAY)
        edges=float(cv2.Canny(gray,80,180).mean())
        denoised=cv2.GaussianBlur(gray,(3,3),0); noise=float(np.std(gray.astype(np.float32)-denoised.astype(np.float32)))
        with Image.open(context.path) as original:
            exif_count=len(original.getexif()); fmt=original.format
            metadata_markers=[]
            for tag_id, raw in original.getexif().items():
                text=str(raw).strip().lower()
                if not text: continue
                if any(marker in text for marker in _EDITING_SOFTWARE_MARKERS):
                    metadata_markers.append({"field": str(tag_id), "kind": "editing_software"})
                if any(marker in text for marker in _AI_GENERATOR_MARKERS):
                    metadata_markers.append({"field": str(tag_id), "kind": "ai_generator"})
            metadata_markers=metadata_markers[:6]
            ela_mean=None
            if fmt == "JPEG":
                buffer=io.BytesIO(); original.convert("RGB").save(buffer,format="JPEG",quality=90)
                buffer.seek(0)
                recompressed=Image.open(buffer).convert("RGB")
                difference=ImageChops.difference(original.convert("RGB"),recompressed)
                ela_mean=round(float(np.asarray(difference).mean()),3)
        measurements={"method":"edge/noise/metadata and JPEG ELA measurements","format":fmt,"edge_density":round(edges,3),"noise_residual_std":round(noise,3),"exif_tag_count":exif_count,"ela_mean_absolute_difference":ela_mean,"metadata_markers":metadata_markers}
        # Extreme ELA differences and near-zero noise are observable image
        # anomalies. They are deliberately a low-severity review signal.
        suspicious_ela=ela_mean is not None and ela_mean>18
        suspicious_noise=noise<.35 and min(gray.shape)>=500
        suspicious_metadata=bool(metadata_markers)
        suspicious=suspicious_ela or suspicious_noise or suspicious_metadata
        measurements["indicators"]={"elevated_ela":suspicious_ela,"unusually_uniform_noise":suspicious_noise,"metadata_editing_or_ai_markers":suspicious_metadata}
        return [EvidenceResult(self.name,"forensic_anomaly" if suspicious else "forensic_measurements",DetectorStatus.DETECTED if suspicious else DetectorStatus.NOT_DETECTED,value=measurements,reliability=.5,confidence=.62 if suspicious else .55,severity=12 if suspicious else 0,dependencies=["image_forensics"],details={"limitations":"Measurements and metadata markers are supporting indicators; no single forensic signal establishes tampering."})]
