from __future__ import annotations
import re
def normalize_id(value: str, document_family: str = "generic") -> str:
    """Apply OCR substitutions only where the field grammar permits digits."""
    cleaned=re.sub(r"[^A-Z0-9]","",value.upper())
    if document_family == "aadhaar": return cleaned.translate(str.maketrans({"O":"0","I":"1","L":"1","S":"5","B":"8"}))
    if document_family == "passport" and len(cleaned)>=2:
        return cleaned[0]+cleaned[1:].translate(str.maketrans({"O":"0","I":"1","L":"1","S":"5","B":"8"}))
    return cleaned
def normalize_text(value: str) -> str: return re.sub(r"\s+"," ",value.strip().upper())
