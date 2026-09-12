from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from core.result_schema import DetectorStatus, EvidenceResult

@dataclass
class AnalysisContext:
    path: Path
    config: dict[str, Any]
    image: Any = None
    preprocessed: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    fields: list[Any] = field(default_factory=list)
    evidence: list[EvidenceResult] = field(default_factory=list)
    submission: dict[str, Any] = field(default_factory=dict)

class Detector(ABC):
    name: str
    @abstractmethod
    def analyse(self, context: AnalysisContext) -> list[EvidenceResult]: ...

def execute(detector: Detector, context: AnalysisContext) -> list[EvidenceResult]:
    try:
        results=detector.analyse(context)
        return results if isinstance(results, list) else [results]
    except Exception as exc:
        logging.getLogger(__name__).exception("detector_failed detector=%s", detector.name)
        return [EvidenceResult(detector.name, "processing_error", DetectorStatus.ERROR, reliability=0, confidence=0, severity=0, error_category=type(exc).__name__)]
