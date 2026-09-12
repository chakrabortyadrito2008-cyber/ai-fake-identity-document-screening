import json
from abc import ABC, abstractmethod
from pathlib import Path
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult
class TrustedSourceProvider(ABC):
    """Contract for a configured organisation-approved lookup provider."""
    @abstractmethod
    def lookup(self, identity_key: str): ...
class LocalSyntheticSource(TrustedSourceProvider):
    def __init__(self, records: dict | None=None): self.records=records or {}
    def lookup(self, identity_key): return self.records.get(identity_key)
    @classmethod
    def from_json(cls, path: str | Path):
        records=json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({str(record["identity_key"]):record for record in records if "identity_key" in record})
class TrustedSource(Detector):
    name="trusted_source"
    def __init__(self, provider: TrustedSourceProvider | None=None): self.provider=provider
    def analyse(self, context):
        if self.provider is None:return [EvidenceResult(self.name,"trusted_validation",DetectorStatus.UNAVAILABLE,details={"reason":"No organisation-approved local or authoritative source is configured"})]
        key=context.submission.get("identity_key")
        if not key:return [EvidenceResult(self.name,"trusted_validation",DetectorStatus.NOT_APPLICABLE,details={"reason":"no submitted identity key"})]
        record=self.provider.lookup(key)
        if record:
            demo_only=bool(record.get("demo_only",False))
            return [EvidenceResult(self.name,"trusted_validation",DetectorStatus.NOT_DETECTED,value="MATCH",reliability=.9 if not demo_only else .35,confidence=float(record.get("confidence",.7)),details={"source":record.get("source","local"),"source_type":"demo local registry" if demo_only else "local organisational record","trust_level":"demo" if demo_only else "local","record_version":record.get("record_version"),"demo_only":demo_only,"not_universal_authority":True})]
        return [EvidenceResult(self.name,"trusted_validation",DetectorStatus.NOT_DETECTED,value="NOT_FOUND",reliability=.9,confidence=.9,details={"source_type":"local organisational/synthetic record","not_found_is_not_fraud":True,"not_universal_authority":True})]
