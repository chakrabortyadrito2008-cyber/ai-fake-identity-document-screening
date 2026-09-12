import json
from pathlib import Path
from types import SimpleNamespace

from modules.liveness_detection import LivenessDetection


def test_liveness_is_not_applied_to_document_portrait():
    root = Path(__file__).parents[1]
    config = json.loads((root / "config" / "settings.json").read_text(encoding="utf-8"))
    config["_root"] = str(root)
    result = LivenessDetection().analyse(SimpleNamespace(config=config, submission={}))[0]
    assert result.status.value == "NOT_APPLICABLE"
