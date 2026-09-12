from __future__ import annotations
import json
from pathlib import Path
import pytest

@pytest.fixture
def pipeline_root(tmp_path: Path) -> Path:
    """Create an isolated, configuration-complete project root for each test."""
    source=Path(__file__).parents[1]
    root=tmp_path / "project"
    (root / "config").mkdir(parents=True)
    (root / "data" / "synthetic_data").mkdir(parents=True)
    (root / "models" / "manifests").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)
    settings=json.loads((source / "config" / "settings.json").read_text(encoding="utf-8"))
    settings["database_path"]="data/test.sqlite3"
    (root / "config" / "settings.json").write_text(json.dumps(settings),encoding="utf-8")
    for filename in ("identities.json","artifacts.json","verification_history.json","confirmed_cases.json"):
        (root / "data" / "synthetic_data" / filename).write_bytes((source / "data" / "synthetic_data" / filename).read_bytes())
    return root
