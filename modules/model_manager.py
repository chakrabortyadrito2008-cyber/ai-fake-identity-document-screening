import hashlib
from pathlib import Path


def verify_model_integrity(path: str, expected_sha256: str) -> bool:
    """Stream-hash a model file and compare against the manifest checksum."""
    p=Path(path)
    if not p.is_file(): return False
    digest=hashlib.sha256()
    with p.open("rb") as model_file:
        for chunk in iter(lambda:model_file.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest().lower()==expected_sha256.lower()


class ModelManager:
    def __init__(self, settings, root: str | Path = "."): self.settings=settings; self.root=Path(root)
    def configured_models(self):
        result={}
        for name, model in self.settings.get("models",{}).items():
            item=dict(model); path=Path(item.get("path", "")); path=path if path.is_absolute() else self.root/path
            item["exists"]=path.is_file(); item["resolved_path"]=str(path)
            checksum=item.get("sha256","")
            item["integrity_verified"]=bool(checksum) and verify_model_integrity(str(path),checksum)
            item["available"]=item["exists"] and item["integrity_verified"] and bool(item.get("license")) and item["license"]!="REQUIRED_BEFORE_ENABLEMENT"
            item["load_status"]="READY" if item["available"] else "UNAVAILABLE"
            result[name]=item
        return result
