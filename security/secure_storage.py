from pathlib import Path
from security.encryption import encrypt
def store(path:Path,data:bytes,key:str)->None:
    """Persist sensitive bytes only when an explicit Fernet key is supplied."""
    if not key: raise ValueError("Encryption key is required for secure storage")
    path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(encrypt(data,key)); path.chmod(0o600)
