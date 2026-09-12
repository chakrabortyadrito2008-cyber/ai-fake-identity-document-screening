from __future__ import annotations
import importlib.util
from pathlib import Path
from typing import Any
from modules.model_manager import ModelManager

class CapabilityManager:
    def __init__(self, config: dict[str, Any], root: str | Path = "."): self.config=config; self.root=Path(root)
    def report(self) -> dict[str, Any]:
        f=self.config["features"]
        tess=bool(importlib.util.find_spec("pytesseract"))
        models=ModelManager(self.config,self.root).configured_models()
        return {
            "ocr": {"available": f["ocr"] and tess, "reason": None if f["ocr"] and tess else "pytesseract disabled or missing"},
            "qr": {"available": f["qr"] and bool(importlib.util.find_spec("cv2")), "reason": None if f["qr"] and importlib.util.find_spec("cv2") else "OpenCV QR decoder required"},
            "forensics": {"available": f["forensics"] and bool(importlib.util.find_spec("cv2")), "reason": None if f["forensics"] and importlib.util.find_spec("cv2") else "OpenCV required"},
            "graph": {"available": f["graph"] and bool(importlib.util.find_spec("networkx")), "reason": None if f["graph"] and importlib.util.find_spec("networkx") else "NetworkX required"},
            "historical_intelligence": {"available": True, "reason": None},
            "trusted_source": {"available": f["trusted_source"] and bool(self.config.get("trusted_source_path")), "reason": "DEMO ONLY — replace with an approved registry before deployment" if self.config.get("trusted_source_mode")=="DEMO_ONLY" else (None if f["trusted_source"] and self.config.get("trusted_source_path") else "No organisation-approved trusted source configured"), "mode": self.config.get("trusted_source_mode","LOCAL")},
            "face_detection": {"available": models.get("yunet",{}).get("available",False), "reason":None if models.get("yunet",{}).get("available",False) else "YuNet requires a present, licensed, SHA-256 verified model"},
            "face_match":{"available":f["face_match"] and models.get("sface",{}).get("available",False),"reason":None if f["face_match"] and models.get("sface",{}).get("available",False) else "SFace requires a present, hash-verified model"},
            "liveness":{"available":f["liveness"] and models.get("minifasnet_v2",{}).get("available",False),"reason":"Ready for a separate live-selfie/video capture; not applied to document portraits" if f["liveness"] and models.get("minifasnet_v2",{}).get("available",False) else "MiniFASNetV2 requires a present, hash-verified model"},
            "deepfake":{"available":f["deepfake"] and models.get("deepfake_detector_v1",{}).get("available",False),"reason":None if f["deepfake"] and models.get("deepfake_detector_v1",{}).get("available",False) else "Deepfake detector requires a present, licensed, SHA-256 verified model"},
            "document_anomaly":{"available":f["document_anomaly"] and bool(self.config.get("anomaly_baseline_path")),"reason":"DEMO ONLY — replace with a calibrated organisation baseline before deployment" if self.config.get("anomaly_baseline_path"," ").endswith("document_anomaly_baseline.json") else (None if f["document_anomaly"] and self.config.get("anomaly_baseline_path") else "No trained, organisation-specific anomaly baseline configured"),"mode":"DEMO_ONLY" if self.config.get("anomaly_baseline_path"," ").endswith("document_anomaly_baseline.json") else "CALIBRATED"}
        }
    def model_manifest_status(self) -> dict[str, Any]:
        return {"models": ModelManager(self.config,self.root).configured_models(), "manifest_dir": str(self.root/"models/manifests")}
