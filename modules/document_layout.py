"""Document geometry and OCR-region analysis.

This is intentionally template-agnostic: it establishes a repeatable layout
description which document-family validators can use, rather than pretending
that OCR boxes alone authenticate a document.
"""
import cv2

from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class DocumentLayout(Detector):
    name = "document_layout"

    def analyse(self, context):
        image = context.preprocessed
        if image is None:
            return [EvidenceResult(self.name, "layout", DetectorStatus.INCONCLUSIVE, details={"reason": "No analysable image"})]
        height, width = image.shape[:2]
        tokens = context.metadata.get("ocr", {}).get("tokens", [])
        text_regions = []
        for token in tokens:
            x, y, w, h = token["box"]
            if w > 0 and h > 0:
                text_regions.append({"box": [int(x), int(y), int(w), int(h)], "text": token["text"], "confidence": token["confidence"]})

        # A document submitted sideways is observable from its geometry.  We
        # report it for review; rotation is deliberately not silently applied
        # after OCR because that would invalidate OCR-region coordinates.
        orientation = "LANDSCAPE" if width >= height else "PORTRAIT"
        gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
        edges = cv2.Canny(gray, 60, 160)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        candidate_regions = []
        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            area = w * h
            if area >= width * height * 0.01 and w >= 20 and h >= 20:
                candidate_regions.append([int(x), int(y), int(w), int(h)])
        candidate_regions.sort(key=lambda box: box[2] * box[3], reverse=True)
        layout = {
            "image_size": [width, height],
            "orientation": orientation,
            "text_regions": text_regions,
            "text_region_count": len(text_regions),
            "visual_region_candidates": candidate_regions[:20],
            "coordinate_system": "pixels, origin top-left",
        }
        context.metadata["regions"] = layout
        return [EvidenceResult(
            self.name, "layout_regions", DetectorStatus.NOT_DETECTED, value=layout,
            reliability=.72, confidence=.75 if text_regions else .45,
            dependencies=["ocr"],
            details={"limitation": "Layout regions describe the submitted image; family-specific template validation remains separate."},
        )]
