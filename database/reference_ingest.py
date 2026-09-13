from __future__ import annotations
import hashlib, json, logging
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_reference_folder(root: Path, config: dict) -> Path | None:
    """Absolute path of the configured reference folder, or None if unusable."""
    folder_raw = str(config.get("reference_database_path", "") or "").strip()
    if not folder_raw:
        return None
    folder = Path(folder_raw)
    if not folder.is_absolute():
        folder = root / folder
    return folder if folder.is_dir() else None


def ingest_reference_database(root: Path, config: dict, repo) -> dict:
    """Ingest a folder of reference document images into the artifact registry.

    Idempotent: a JSON cache keyed by file content hash skips files that were
    already ingested unchanged. Every reference image is registered with its
    SHA-256 and pHash under a `registry:<filename>` identity key. Screening
    then matches uploads against these fingerprints (exact bytes via SHA-256,
    or perceptually via pHash distance) as positive database evidence.
    """
    folder_raw = str(config.get("reference_database_path", "") or "").strip()
    if not folder_raw:
        return {"available": False, "reason": "No reference database folder configured", "records": 0}
    folder = Path(folder_raw)
    if not folder.is_absolute():
        folder = root / folder
    if not folder.is_dir():
        return {"available": False, "reason": f"Reference database folder not found: {folder_raw}", "records": 0}

    (root / "data").mkdir(parents=True, exist_ok=True)
    cache_path = root / "data" / "reference_cache.json"
    cache: dict = {}
    if cache_path.is_file():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("reference cache unreadable; rebuilding", exc_info=True)

    from core.result_schema import utcnow
    from PIL import Image
    import imagehash

    supported = {".png", ".jpg", ".jpeg", ".webp"}
    files = sorted(p for p in folder.iterdir() if p.suffix.lower() in supported and p.is_file())
    added = unchanged = errors = 0
    dirty = False
    for path in files:
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            cached = cache.get(str(path))
            if cached and cached.get("sha256") == digest:
                unchanged += 1
                continue
            phash = str(imagehash.phash(Image.open(path)))
            repo.register_reference(sha=digest, phash=phash, identity_key=f"registry:{path.name}", label=path.name)
            cache[str(path)] = {"sha256": digest, "phash": phash, "label": path.name, "ingested_at": utcnow()}
            added += 1
            dirty = True
        except Exception:
            errors += 1
            logger.exception("reference ingest failed for %s", path)
    if dirty:
        try:
            cache_path.write_text(json.dumps(cache, indent=1), encoding="utf-8")
        except Exception:
            logger.exception("reference cache write failed")

    count = repo.reference_count()
    logger.info("reference_database_ingest folder=%s new=%d unchanged=%d errors=%d total=%d", folder_raw, added, unchanged, errors, count)
    return {
        "available": count > 0,
        "reason": None if count > 0 else "Reference folder contained no readable images",
        "records": count, "new": added, "unchanged": unchanged, "errors": errors,
        "folder": str(folder),
    }
