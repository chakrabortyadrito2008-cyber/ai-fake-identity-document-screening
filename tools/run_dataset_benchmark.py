"""Resumable, privacy-conscious batch benchmark for a local image folder.

Uses the fast triage path by default: every image is validated, OCR/layout/
quality/provenance checks run and its result is persisted. Deepfake inference is
deferred because CPU inference over hundreds of images is intentionally costly.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Allow direct `python tools/run_dataset_benchmark.py ...` execution.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.pipeline import FraudPipeline


def report_payload(source: Path, started: str, rows: list[dict], total: int, mode: str) -> dict:
    return {
        "benchmark_version": "1.0",
        "started_at": started,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source_folder": str(source),
        "analysis_mode": mode,
        "total_files": total,
        "processed_files": len(rows),
        "complete": len(rows) == total,
        "triage_counts": dict(Counter(row["triage"] for row in rows)),
        "document_type_counts": dict(Counter(row["document_type"] for row in rows)),
        "quality_counts": dict(Counter(row["quality"] for row in rows)),
        "results": rows,
    }


def write_report(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a resumable document-folder benchmark")
    parser.add_argument("folder")
    parser.add_argument("--mode", choices=("fast", "full"), default="fast")
    parser.add_argument("--report", default="data/benchmarks/aadhaar_generated_benchmark.json")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()
    root = PROJECT_ROOT
    source = Path(args.folder).resolve()
    if not source.is_dir(): parser.error("folder does not exist")
    if args.checkpoint_every < 1: parser.error("checkpoint-every must be at least 1")
    files = sorted(path for path in source.iterdir() if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"})
    report_path = Path(args.report)
    if not report_path.is_absolute(): report_path = root / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    prior = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    rows = prior.get("results", [])
    completed = {row["filename"] for row in rows}
    started = prior.get("started_at", datetime.now(timezone.utc).isoformat())
    pipeline = FraudPipeline(root)
    pending = [path for path in files if path.name not in completed]
    print(f"Benchmark start: {len(completed)}/{len(files)} complete; {len(pending)} pending", flush=True)
    overall_started = time.monotonic()
    for index, path in enumerate(pending, start=1):
        item_started = time.monotonic()
        try:
            result = pipeline.screen(
                path,
                identity_key=f"benchmark:aadhaar-generated:{path.stem}",
                request_id=f"benchmark:{path.name}",
                analysis_mode=args.mode,
            )
            template = next((item for item in result["evidence"] if item["detector"] == "aadhaar_template"), {})
            rows.append({
                "filename": path.name,
                "screening_id": result["screening_id"],
                "triage": result["triage"]["label"],
                "status": result["status"],
                "risk_score": result["risk_score"],
                "document_type": result["document_type"]["value"],
                "quality": result["quality"].get("status"),
                "aadhaar_template": template.get("signal"),
                "detected_signals": [item["signal"] for item in result["evidence"] if item["status"] == "DETECTED"],
                "elapsed_seconds": round(time.monotonic() - item_started, 2),
            })
        except Exception as exc:
            rows.append({"filename": path.name, "triage": "NEEDS MANUAL VERIFICATION", "status": "INSUFFICIENT EVIDENCE", "risk_score": None, "document_type": "UNKNOWN", "quality": "ERROR", "aadhaar_template": None, "detected_signals": [], "error": type(exc).__name__, "elapsed_seconds": round(time.monotonic() - item_started, 2)})
        if index % args.checkpoint_every == 0 or index == len(pending):
            payload = report_payload(source, started, rows, len(files), args.mode)
            payload["elapsed_seconds"] = round(time.monotonic() - overall_started, 2)
            write_report(report_path, payload)
            print(f"Checkpoint: {len(rows)}/{len(files)} processed", flush=True)
    print(f"Benchmark complete: {report_path}", flush=True)


if __name__ == "__main__":
    main()
