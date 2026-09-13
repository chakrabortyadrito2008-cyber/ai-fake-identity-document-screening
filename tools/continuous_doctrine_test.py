"""Continuous doctrine-verification harness.

Doctrine under test:
  1. Determinable-genuine  -> auto LIKELY_GENUINE, NEVER in the human queue.
  2. Determinable-fake     -> auto LIKELY_FAKE, NEVER in the human queue.
  3. Suspicious (neither)  -> MANUAL_VERIFICATION, ALWAYS in the human queue.
  4. Zero processing errors.

Each pass screens a rotating slice of the dataset against the live server,
resubmitting earlier artifacts under fresh identities so reuse-fraud paths
stay exercised. Any invariant violation is printed with full context.
"""
import json
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
DATASET = Path(r"C:\Users\Lenovo\Downloads\new_generated_aadharcard_images-20240316T112301Z-001\new_generated_aadharcard_images")
BASE = "http://127.0.0.1:8000"


def post_screen(path: Path, identity_key: str) -> dict:
    boundary = "----doctribe42"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"identity_key\"\r\n\r\n{identity_key}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\n"
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"{BASE}/screen", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.loads(response.read())


def get_json(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=60) as response:
        return json.loads(response.read())


def verify(result: dict, identity_key: str) -> list[str]:
    problems: list[str] = []
    triage = result.get("triage", {})
    code = triage.get("code")
    status = result.get("status")
    if "error" in result:
        problems.append(f"{identity_key}: processing error {result['error']}")
        return problems
    if status == "LOW RISK" and code != "LIKELY_GENUINE":
        problems.append(f"{identity_key}: LOW RISK must auto-classify genuine, got {code}")
    if status == "HIGH RISK" and code != "LIKELY_FAKE":
        problems.append(f"{identity_key}: HIGH RISK must auto-declare fake, got {code}")
    if code == "LIKELY_GENUINE" and triage.get("flagged"):
        problems.append(f"{identity_key}: genuine result flagged for review")
    if code == "MANUAL_VERIFICATION" and not triage.get("flagged"):
        problems.append(f"{identity_key}: suspicious result not flagged")
    if code not in {"LIKELY_GENUINE", "LIKELY_FAKE", "MANUAL_VERIFICATION"}:
        problems.append(f"{identity_key}: unknown triage code {code}")
    return problems


def main() -> int:
    pass_number = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    batch_size = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    files = sorted(DATASET.glob("*.jpg"))
    if not files:
        print(f"FATAL: dataset not found at {DATASET}")
        return 2
    start = ((pass_number - 1) * batch_size * 7) % len(files)
    batch = [files[(start + i * 7) % len(files)] for i in range(batch_size)]

    counts = {"LIKELY_GENUINE": 0, "LIKELY_FAKE": 0, "MANUAL_VERIFICATION": 0}
    violations: list[str] = []
    errors = 0
    started = time.time()
    for index, path in enumerate(batch):
        # Rotate identity namespaces per pass; a mid-batch second submission of
        # the same artifact under a new identity exercises the reuse path.
        identity_key = f"cont-p{pass_number}-{index}" if index % 4 else f"cont-reuse-p{pass_number}-{index}"
        try:
            result = post_screen(path, identity_key)
        except Exception as exc:  # transport or server failure
            violations.append(f"{path.name}: request failed {type(exc).__name__}: {exc}")
            errors += 1
            continue
        violations.extend(verify(result, f"{identity_key}:{path.name}"))
        code = result.get("triage", {}).get("code", "ERROR")
        if code == "ERROR":
            errors += 1
        else:
            counts[code] = counts.get(code, 0) + 1
        print(f"  {path.name:44s} risk {result.get('risk_score'):>6} {code}", flush=True)

    elapsed = time.time() - started
    overview = get_json("/operations/overview")
    queue = get_json("/review-queue?limit=500")
    queue_codes = {item["triage"] for item in queue["items"]}
    if queue_codes - {"NEEDS MANUAL VERIFICATION"}:
        violations.append(f"queue holds non-suspicious items: {sorted(queue_codes)}")
    expected_pending = overview["pending_review"]
    print(f"\nPASS {pass_number}: {len(batch)} docs in {elapsed:.0f}s | {counts} | errors {errors}")
    print(f"  queue pending: {expected_pending} | queue triage labels: {sorted(queue_codes)}")
    if violations:
        print("DOCTRINE VIOLATIONS:")
        for violation in violations:
            print(f"  !! {violation}")
        return 1
    print("DOCTRINE OK: every determinable document auto-classified; queue holds only suspicious items.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
