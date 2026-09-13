from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any

def load_local_env(path: str | Path) -> None:
    """Load simple local KEY=VALUE settings without overriding real environment values."""
    env_path=Path(path)
    if not env_path.is_file(): return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line=raw_line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key,value=line.split("=",1); key=key.strip(); value=value.strip().strip('"').strip("'")
        if key and key.replace("_","").isalnum(): os.environ.setdefault(key,value)

class ConfigurationError(ValueError):
    """Raised before processing when local settings are unsafe or incomplete."""

def load_settings(root: str | Path) -> dict[str, Any]:
    path=Path(root)/"config/settings.json"
    try: settings=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise ConfigurationError(f"Cannot load settings: {type(exc).__name__}") from exc
    required={"version","database_path","supported_extensions","max_file_bytes","max_pixels","quality","ocr","risk","features","api","processing","models","retention_days"}
    missing=required-settings.keys()
    if missing: raise ConfigurationError(f"Missing configuration keys: {', '.join(sorted(missing))}")
    if not isinstance(settings["supported_extensions"],list) or not settings["supported_extensions"] or any(not isinstance(x,str) or not x.startswith(".") for x in settings["supported_extensions"]): raise ConfigurationError("supported_extensions must be a non-empty extension list")
    if settings["max_file_bytes"]<=0 or settings["max_pixels"]<=0 or settings["retention_days"]<1: raise ConfigurationError("File, pixel, and retention limits must be positive")
    risk=settings["risk"]
    if not 0<=risk["review_threshold"]<risk["high_threshold"]<=100 or not 0<risk["max_single_evidence"]<=100: raise ConfigurationError("Risk thresholds must satisfy safe bounds")
    processing=settings["processing"]
    if not 0<processing["max_ocr_variants"]<=10: raise ConfigurationError("Processing limits are outside safe bounds")
    if not isinstance(settings["api"]["max_batch_size"],int) or settings["api"]["max_batch_size"]<0: raise ConfigurationError("max_batch_size must be a non-negative integer (0 = unlimited)")
    if not 1<=int(processing.get("max_pdf_pages", 0))<=50 or not 72<=int(processing.get("pdf_render_dpi", 0))<=300: raise ConfigurationError("PDF processing limits are outside safe bounds")
    return settings
