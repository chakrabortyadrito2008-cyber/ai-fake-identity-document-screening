from __future__ import annotations
import importlib.util, json, logging, os, shutil, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from core.analysis_engine import AnalysisContext, execute
from core.config import load_settings
from core.environment import load_local_env
from core.capability_manager import CapabilityManager
from core.evidence_fusion import EvidenceFusion
from core.risk_engine import RiskEngine
from core.analysis_receipt import build_receipt
from core.triage import triage_result
from core.deployment_readiness import assess
from core.result_schema import DetectorStatus, EvidenceResult, Outcome, utcnow
from database.db_manager import DatabaseManager
from database.repositories import ScreeningRepository
from modules.input_validator import InputValidator
from modules.preprocessing import Preprocessor
from modules.image_quality import ImageQuality
from modules.ocr_engine import OCREngine
from modules.document_type import DocumentTypeDetector
from modules.document_layout import DocumentLayout
from modules.aadhaar_template import AadhaarTemplate
from modules.identity_extractor import IdentityExtractor
from modules.field_confidence import FieldConfidence
from modules.cross_document_consistency import CrossDocumentConsistency
from modules.document_validator import DocumentValidator
from modules.trusted_source import LocalSyntheticSource, TrustedSource
from modules.qr_verification import QRVerification
from modules.security_features import SecurityFeatures
from modules.fingerprinting import Fingerprinting
from modules.provenance import Provenance
from modules.artifact_intelligence import ArtifactIntelligence
from modules.forensics import Forensics
from modules.manipulation_detection import ManipulationDetection
from modules.graph_analysis import GraphAnalysis
from modules.temporal_analysis import TemporalAnalysis
from modules.behavioural_analysis import BehaviouralAnalysis
from modules.attack_detection import AttackDetection
from modules.anomaly_detection import AnomalyDetection
from modules.face_detection import FaceDetection
from modules.face_quality import FaceQuality
from modules.face_document_match import FaceDocumentMatch
from modules.liveness_detection import LivenessDetection
from modules.deepfake_detection import DeepfakeDetection
from modules.presentation_attack import PresentationAttack
from modules.explanation import explain

class FraudPipeline:
    def __init__(self, root: str | Path):
        self.root=Path(root).resolve(); load_local_env(self.root/".env"); self.config=load_settings(self.root)
        db_path=Path(self.config["database_path"]); self.db=DatabaseManager(self.root/db_path if not db_path.is_absolute() else db_path); self.repo=ScreeningRepository(self.db)
        self.config["_root"]=str(self.root); self.capabilities=CapabilityManager(self.config,self.root)
        source_path=self.config.get("trusted_source_path","")
        path=Path(source_path)
        if source_path and not path.is_absolute(): path=self.root/path
        self.trusted_source=TrustedSource(LocalSyntheticSource.from_json(path) if source_path and path.is_file() else None)
    def _detectors(self):
        return [InputValidator(),Preprocessor(),ImageQuality(),OCREngine(),DocumentTypeDetector(),DocumentLayout(),IdentityExtractor(),FieldConfidence(),DocumentValidator(),self.trusted_source,QRVerification(),SecurityFeatures(),Fingerprinting(),Forensics(),ManipulationDetection(),FaceDetection(),AadhaarTemplate(),FaceQuality(),FaceDocumentMatch(),LivenessDetection(),PresentationAttack(),DeepfakeDetection(),AnomalyDetection(),CrossDocumentConsistency(self.repo),Provenance(self.repo),ArtifactIntelligence(self.repo),GraphAnalysis(self.repo),TemporalAnalysis(self.repo),BehaviouralAnalysis(),AttackDetection(self.repo)]
    def screen(self, file_path: str | Path, identity_key: str | None=None, request_id: str | None=None, reference_face_path: str | Path | None=None, live_selfie_path: str | Path | None=None, analysis_mode: str = "full") -> dict[str,Any]:
        if analysis_mode not in {"fast", "full"}: raise ValueError("analysis_mode must be 'fast' or 'full'")
        request_id=request_id or str(uuid.uuid4()); context=AnalysisContext(Path(file_path).resolve(),self.config,submission={"identity_key":identity_key,"reference_face_path":str(reference_face_path) if reference_face_path else None,"live_selfie_path":str(live_selfie_path) if live_selfie_path else None,"analysis_mode":analysis_mode})
        evidence=[]; quality_blocked=False
        blocked_by_quality={"document_type","document_layout","ocr_engine","identity_extractor","field_confidence","document_validator","qr_verification","security_features","forensics","face_detection","aadhaar_template","face_quality","face_document_match","liveness_detection","presentation_attack","deepfake_detection","anomaly_detection"}
        for d in self._detectors():
            if quality_blocked and d.name in blocked_by_quality:
                results=[EvidenceResult(d.name,"blocked_by_quality_gate",DetectorStatus.INCONCLUSIVE,details={"reason":"Document quality is insufficient for reliable downstream analysis"},dependencies=["image_quality"])]
            else:
                results=execute(d,context)
            evidence.extend(results); context.evidence.extend(results)
            if d.name=="input_validator" and any(r.status.value=="ERROR" for r in results): break
            if d.name=="preprocessing" and any(r.status==DetectorStatus.ERROR for r in results): quality_blocked=True
            if d.name=="image_quality" and (any(r.status==DetectorStatus.ERROR for r in results) or context.metadata.get("quality",{}).get("status")=="INSUFFICIENT_QUALITY"): quality_blocked=True
        score, fusion=EvidenceFusion().fuse(evidence,self.config["risk"].get("max_single_evidence"))
        quality=context.metadata.get("quality",{}); analyzable=quality.get("status") in {"ANALYSABLE","PARTIALLY_ANALYSABLE"}
        detected=[e for e in evidence if e.status.value=="DETECTED"]
        outcome, confidence=RiskEngine(self.config).evaluate(score,analyzable,len(detected))
        # Do not allow a high-confidence attack indicator to be hidden by a
        # conservative fused-score threshold. It warrants human review even
        # when it is a single independent signal.
        strong_signal=any((item.severity >= 20 and item.confidence >= .8) or item.signal in {"aadhaar_template_inconsistent", "qr_content_mismatch", "face_mismatch"} for item in detected)
        if outcome == Outcome.LOW_RISK and strong_signal:
            outcome, confidence = Outcome.REVIEW, "MEDIUM"
        public_provenance=dict(context.metadata.get("provenance",{})); prior_identities=public_provenance.pop("identities",[]); public_provenance["identity_count"]=len(prior_identities)
        result={"screening_id":str(uuid.uuid4()),"request_id":request_id,"timestamp":utcnow(),"filename":context.path.name,"analysis_mode":analysis_mode,"status":outcome.value,"risk_score":round(score,2),"risk_score_is_probability":False,"confidence":confidence,"document_type":context.metadata.get("document_type",{"value":"UNKNOWN","confidence":0}),"identity":{"fields":[f.safe_dict() for f in context.fields]},"quality":quality,"ocr":{"available":"ocr" in context.metadata,"confidence":context.metadata.get("ocr",{}).get("confidence")},"fingerprints":context.metadata.get("fingerprint",{}),"provenance":public_provenance,"graph":context.metadata.get("graph",{}),"evidence":[e.as_dict() for e in evidence],"evidence_fusion":fusion,"explanation":explain(evidence,fusion,score),"limitations":[e.details.get("reason",e.signal) for e in evidence if e.status in {DetectorStatus.UNAVAILABLE,DetectorStatus.INCONCLUSIVE}],"capabilities":self.capabilities.report(),"versions":{"software":self.config["version"],"config":self.config["version"],"database_schema":1,"ocr":context.metadata.get("ocr",{}).get("engine")}}
        result["triage"]=triage_result(outcome.value, quality, result["risk_score"], evidence)
        result["analysis_receipt"]=build_receipt(result, self.capabilities.model_manifest_status()["models"])
        fp=context.metadata.get("fingerprint")
        if fp:
            self.repo.record(fp["sha256"],fp["phash"],identity_key,outcome.value,score,result,result["screening_id"])
            self.repo.audit("screen",request_id,{"screening_id":result["screening_id"],"outcome":outcome.value})
        logging.getLogger(__name__).info("screen_complete request_id=%s outcome=%s",request_id,outcome.value)
        return result
    def screen_folder(self, folder_path: str | Path, identity_key_prefix: str | None=None, analysis_mode: str = "fast", limit: int | None = None) -> dict[str,Any]:
        folder=Path(folder_path).resolve()
        if not folder.is_dir(): raise ValueError("Input folder does not exist or is not a directory")
        files=sorted(path for path in folder.iterdir() if path.is_file() and path.suffix.lower() in self.config["supported_extensions"])
        if limit is not None:
            if limit < 1: raise ValueError("limit must be at least 1")
            files=files[:limit]
        batch_id=str(uuid.uuid4()); results=[]
        for index,path in enumerate(files):
            key=f"{identity_key_prefix}:{path.stem}" if identity_key_prefix else None
            try: results.append(self.screen(path,key,request_id=f"{batch_id}:{index}",analysis_mode=analysis_mode))
            except Exception as exc: results.append({"filename":path.name,"status":"INSUFFICIENT EVIDENCE","triage":{"code":"MANUAL_VERIFICATION","label":"NEEDS MANUAL VERIFICATION","flagged":True,"reason":"Processing failure"},"error":type(exc).__name__})
        counts={}
        for item in results:
            label=item.get("triage",{}).get("label",item.get("status","ERROR")); counts[label]=counts.get(label,0)+1
        report={"batch_id":batch_id,"created_at":datetime.now(timezone.utc).isoformat(),"source_folder":str(folder),"analysis_mode":analysis_mode,"file_count":len(files),"triage_counts":counts,"results":results}
        report_dir=folder/"screening_reports"; report_dir.mkdir(exist_ok=True)
        report_path=report_dir/f"screening_report_{batch_id}.json"; report_path.write_text(json.dumps(report,indent=2),encoding="utf-8")
        report["report_path"]=str(report_path)
        return report
    def self_test(self) -> dict[str,Any]:
        checks={"configuration":all(k in self.config for k in ("version","quality","ocr","risk","api","models")),"database":self.db.path.is_file(),"directories":all((self.root/x).is_dir() for x in ("config","data","models","logs")),"tesseract":bool(shutil.which("tesseract") or os.getenv("TESSERACT_PATH")),"dependencies":{name:bool(importlib.util.find_spec(name)) for name in ("fastapi","cv2","numpy","PIL","pytesseract","networkx","sklearn")}}
        capabilities=self.capabilities.report()
        return {"ok":all([checks["configuration"],checks["database"],checks["directories"]]),"python":sys.version,"database":str(self.db.path),"checks":checks,"capabilities":capabilities,"deployment_readiness":assess(self.config,capabilities),"models":self.capabilities.model_manifest_status()}
