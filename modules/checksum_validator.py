"""Deterministic identifier-integrity checks: Aadhaar Verhoeff checksum and PAN
holder-type semantics.

A format regex only proves a number *looks like* an Aadhaar/PAN number. These
checksums prove whether it could have been issued at all. Fabricated IDs — the
cheapest way to fake an identity document — fail here deterministically, with no
model, network call, or reference data.

A valid checksum does NOT mean the number was issued by UIDAI/Income Tax to the
presenter; it means the number is structurally issuable. Real issuance status
requires an authorised verification service, which this offline-first system
deliberately never assumes.
"""
from __future__ import annotations
import re
from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult

# Verhoeff tables: dihedral-group multiplication (d), permutation (p).
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
      [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
      [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
      [9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
      [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
      [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def verhoeff_valid(digits: str) -> bool:
    """True iff the digit string passes the Verhoeff check (last digit = check digit)."""
    if not digits or not digits.isdigit() or len(digits) < 2: return False
    c = 0
    for pos, ch in enumerate(reversed(digits)):
        c = _D[c][_P[pos % 8][int(ch)]]
    return c == 0

def verhoeff_check_digit(first_digits: str) -> str | None:
    """Return the check digit that makes first_digits+check pass, else None."""
    if not first_digits or not first_digits.isdigit(): return None
    for candidate in range(10):
        if verhoeff_valid(first_digits + str(candidate)): return str(candidate)
    return None

# PAN 4th character: holder type per Income Tax Department structure.
_PAN_HOLDER_TYPES = set("PCHFATBLJG")

class ChecksumValidator(Detector):
    name = "checksum_validator"
    def analyse(self, context):
        doc_type = context.metadata.get("document_type", {}).get("value", "UNKNOWN")
        id_fields = [f for f in context.fields if f.name == "id_number" and f.normalized_value]
        findings = []
        for f in id_fields:
            value = f.normalized_value
            if doc_type in {"AADHAAR", "AADHAAR_PROBABLE"} and re.fullmatch(r"\d{12}", value):
                if not verhoeff_valid(value):
                    probable = doc_type == "AADHAAR_PROBABLE"
                    findings.append(EvidenceResult(
                        self.name, "id_checksum_invalid", DetectorStatus.DETECTED,
                        value={"scheme": "verhoeff", "document_type": doc_type, "last4": value[-4:]},
                        reliability=.85 if probable else .95,
                        confidence=.85 if probable else .95,
                        severity=25 if probable else 30, dependencies=["ocr"],
                        details={"semantic": "Verhoeff checksum failure: this number cannot have been issued in this form",
                                 "type_basis": "12-digit number + government marker, brand keyword unread" if probable else "confirmed Aadhaar classification",
                                 "limitation": "OCR digit misreads can also fail a checksum; a valid checksum does not prove issuance to the presenter"}))
            elif doc_type == "PAN" and re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", value):
                holder = value[3]
                if holder not in _PAN_HOLDER_TYPES:
                    findings.append(EvidenceResult(
                        self.name, "pan_holder_type_invalid", DetectorStatus.DETECTED,
                        value={"document_type": "PAN", "holder_type_char": holder},
                        reliability=.9, confidence=.9, severity=25, dependencies=["ocr"],
                        details={"semantic": "PAN 4th character is not a valid holder type (P,C,H,F,A,T,B,L,J,G)",
                                 "limitation": "Structural check only; not a registry lookup"}))
        if findings: return findings
        if not id_fields:
            return [EvidenceResult(self.name, "checksum_validation", DetectorStatus.NOT_APPLICABLE,
                                   details={"reason": "No identifier field was extracted"}, dependencies=["ocr"])]
        return [EvidenceResult(self.name, "checksum_validation", DetectorStatus.NOT_DETECTED,
                               value={"document_type": doc_type, "checked_count": len(id_fields)},
                               reliability=.9, confidence=.9, dependencies=["ocr"], details={} if doc_type != "AADHAAR_PROBABLE" else {"type_basis": "12-digit number + government marker; brand keyword not OCR-readable"})]
