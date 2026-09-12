from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

class DetectorStatus(str, Enum):
    DETECTED="DETECTED"; NOT_DETECTED="NOT_DETECTED"; INCONCLUSIVE="INCONCLUSIVE"; UNAVAILABLE="UNAVAILABLE"; NOT_APPLICABLE="NOT_APPLICABLE"; ERROR="ERROR"

class Outcome(str, Enum):
    LOW_RISK="LOW RISK"; REVIEW="REVIEW REQUIRED"; HIGH_RISK="HIGH RISK"; INSUFFICIENT="INSUFFICIENT EVIDENCE"

@dataclass
class EvidenceResult:
    detector: str
    signal: str
    status: DetectorStatus
    value: Any = None
    reliability: float = 0.0
    confidence: float = 0.0
    severity: float = 0.0
    source: str = "local"
    dependencies: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    error_category: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out=asdict(self); out["status"]=self.status.value; return out

@dataclass
class FieldValue:
    name: str; value: str; normalized_value: str; confidence: float
    source_region: str = "full_document"; extraction_method: str = "ocr"; ocr_confidence: float = 0.0; validation_status: str = "UNVALIDATED"
    def safe_dict(self) -> dict[str, Any]:
        d=asdict(self)
        if self.name in {"id_number", "phone", "address"} and len(self.value)>4:
            d["value"]="*"*(len(self.value)-4)+self.value[-4:]
            d["normalized_value"]="*"*(len(self.normalized_value)-4)+self.normalized_value[-4:]
        return d

def utcnow() -> str: return datetime.now(timezone.utc).isoformat()
