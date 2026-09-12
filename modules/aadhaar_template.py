"""Privacy-preserving e-Aadhaar landscape template-consistency check.

This detects gross layout inconsistencies only. A template match cannot prove
that an Aadhaar is authentic; a UIDAI Secure QR/offline verification is needed
for that claim.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.analysis_engine import Detector
from core.result_schema import DetectorStatus, EvidenceResult


class AadhaarTemplate(Detector):
    name = "aadhaar_template"

    def _profile(self, context):
        path = Path(context.config.get("_root", ".")) / "config" / "aadhaar_template_profile.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, KeyError):
            return None

    def analyse(self, context):
        profile = self._profile(context)
        if profile is None:
            return [EvidenceResult(self.name, "aadhaar_template", DetectorStatus.UNAVAILABLE, details={"reason": "Aadhaar layout profile unavailable"})]
        text = context.metadata.get("ocr", {}).get("raw_text", "").upper()
        groups = profile["marker_groups"]
        marker_matches = [any(marker in text for marker in group) for group in groups]
        likely_aadhaar = context.metadata.get("document_type", {}).get("value") == "AADHAAR" or sum(marker_matches) >= 2
        if not likely_aadhaar:
            return [EvidenceResult(self.name, "aadhaar_template", DetectorStatus.NOT_APPLICABLE, details={"reason": "Document is not classified as Aadhaar"})]
        height, width = context.preprocessed.shape[:2]
        aspect = width / height
        aspect_ok = abs(aspect - float(profile["expected_aspect_ratio"])) <= float(profile["aspect_ratio_tolerance"])
        face_position = "NOT_AVAILABLE"
        faces = context.metadata.get("faces", [])
        if faces:
            x, y, face_width, face_height = faces[0]["box"]
            left, top, right, bottom = profile["expected_face_region"]
            center_x, center_y = (x + face_width / 2) / width, (y + face_height / 2) / height
            face_position = "EXPECTED_REGION" if left <= center_x <= right and top <= center_y <= bottom else "UNEXPECTED_REGION"
        failures = []
        if sum(marker_matches) < int(profile["minimum_marker_groups"]): failures.append("insufficient_expected_markers")
        if not aspect_ok: failures.append("unexpected_landscape_aspect_ratio")
        if face_position == "UNEXPECTED_REGION": failures.append("photo_outside_expected_region")
        value = {"profile_id": profile["profile_id"], "marker_groups_matched": sum(marker_matches), "marker_group_count": len(groups), "aspect_ratio": round(aspect, 3), "aspect_ratio_expected": profile["expected_aspect_ratio"], "face_position": face_position}
        context.metadata["aadhaar_template"] = value
        if failures:
            return [EvidenceResult(self.name, "aadhaar_template_inconsistent", DetectorStatus.DETECTED, value=value, reliability=.55, confidence=min(.9, .45 + .15 * len(failures)), severity=18, dependencies=["aadhaar_layout"], details={"failed_checks": failures, "limitation": "Layout inconsistency is a review signal, not proof of forgery. A matching layout is not UIDAI authentication."})]
        return [EvidenceResult(self.name, "aadhaar_template_consistent", DetectorStatus.NOT_DETECTED, value=value, reliability=.55, confidence=.75, dependencies=["aadhaar_layout"], details={"limitation": "Template consistency is not UIDAI authentication. Verify the digitally signed Secure QR/offline data where available."})]
