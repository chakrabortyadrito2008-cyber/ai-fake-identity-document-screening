import hashlib
from pathlib import Path
class ModelIntegrity:
    @staticmethod
    def verify(path: str, expected_sha256: str) -> bool:
        p=Path(path)
        if not p.is_file(): return False
        digest=hashlib.sha256()
        with p.open("rb") as model_file:
            for chunk in iter(lambda:model_file.read(1024*1024),b""): digest.update(chunk)
        return digest.hexdigest().lower()==expected_sha256.lower()
