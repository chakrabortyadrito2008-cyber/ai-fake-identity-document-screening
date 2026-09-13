"""Analyze a completed benchmark report and print a structured quality summary.

Usage:
    python tools/analyze_benchmark.py data/benchmarks/aadhaar_benchmark_v3_fresh.json
Optionally pass a second (older) report to compare triage behavior across runs:
    python tools/analyze_benchmark.py <new.json> <old.json>
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

VARIANT_MARKERS = ("blurred", "contrast_adjusted", "hue_sat_adjusted", "scaled_up", "scaled_down")


def variant_of(filename: str) -> str:
    name = filename.lower()
    side = "back" if "backside" in name else "front"
    for marker in VARIANT_MARKERS:
        if marker in name:
            return f"{side}:{marker}"
    return f"{side}:original"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def analyze(report: dict, title: str) -> None:
    rows = report.get("results", [])
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")
    print(f"files: {len(rows)}  "
          f"elapsed: {round(report.get('elapsed_seconds', 0), 1)}s")

    triage = Counter(row.get("triage") for row in rows)
    print("\n-- triage distribution --")
    for label, count in triage.most_common():
        print(f"  {label:<38} {count:>5}  ({count * 100 // max(1, len(rows))}%)")

    quality = Counter(row.get("quality") for row in rows)
    print("\n-- quality gates --")
    for label, count in quality.most_common():
        print(f"  {label:<38} {count:>5}")

    doctypes = Counter(row.get("document_type") for row in rows)
    print("\n-- document type detection --")
    for label, count in doctypes.most_common():
        print(f"  {label:<38} {count:>5}")

    signals = Counter()
    for row in rows:
        for signal in row.get("detected_signals", []):
            signals[signal] += 1
    print("\n-- detected signals --")
    for signal, count in signals.most_common():
        print(f"  {signal:<38} {count:>5}  ({count * 100 // max(1, len(rows))}%)")

    scored = [row for row in rows if isinstance(row.get("risk_score"), (int, float))]
    if scored:
        average = sum(row["risk_score"] for row in scored) / len(scored)
        highs = sum(1 for row in scored if row["risk_score"] >= 60)
        print(f"\n-- risk scores --\n  mean: {average:.2f}  >=60 (HIGH): {highs}  max: "
              f"{max(row['risk_score'] for row in scored)}")

    errors = [row for row in rows if row.get("error")]
    print(f"\n-- processing errors: {len(errors)}")
    for row in errors[:5]:
        print(f"  {row.get('filename')}: {row.get('error')}")

    by_variant = defaultdict(list)
    for row in rows:
        by_variant[variant_of(row.get("filename", ""))].append(row)
    print("\n-- per-variant behavior (checksum-fail rate, mean risk, manual-review rate) --")
    print(f"  {'variant':<28}{'n':>5}{'checksum%':>11}{'risk':>7}{'manual%':>9}")
    for variant in sorted(by_variant):
        group = by_variant[variant]
        n = len(group)
        checksum_fail = sum(1 for r in group if "id_checksum_invalid" in r.get("detected_signals", []))
        risks = [r["risk_score"] for r in group if isinstance(r.get("risk_score"), (int, float))]
        manual = sum(1 for r in group if r.get("triage") == "NEEDS MANUAL VERIFICATION")
        mean_risk = sum(risks) / len(risks) if risks else 0
        print(f"  {variant:<28}{n:>5}{checksum_fail * 100 // max(1, n):>10}%{mean_risk:>7.1f}{manual * 100 // max(1, n):>8}%")


def compare(new: dict, old: dict) -> None:
    rows_new = new.get("results", [])
    old_by_name = {row.get("filename"): row for row in old.get("results", [])}
    print(f"\n{'=' * 72}\nCROSS-RUN COMPARISON: new run vs Sept-12 (pre-upgrade) run\n{'=' * 72}")
    flipped = []
    for row in rows_new:
        prior = old_by_name.get(row.get("filename"))
        if prior and prior.get("triage") != row.get("triage"):
            flipped.append((row.get("filename"), prior.get("triage"), row.get("triage")))
    print(f"files with changed triage: {len(flipped)} / {len(rows_new)}")
    transitions = Counter((before, after) for _, before, after in flipped)
    for (before, after), count in transitions.most_common():
        print(f"  {before}  ->  {after}: {count}")
    checksum_now = sum(1 for row in rows_new if "id_checksum_invalid" in row.get("detected_signals", []))
    checksum_before = sum(1 for row in old.get("results", []) if "id_checksum_invalid" in row.get("detected_signals", []))
    print(f"checksum-fail detections: old run {checksum_before} -> new run {checksum_now}")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    report = load(Path(sys.argv[1]))
    analyze(report, f"BENCHMARK: {Path(sys.argv[1]).name}")
    if len(sys.argv) >= 3:
        compare(report, load(Path(sys.argv[2])))


if __name__ == "__main__":
    main()
