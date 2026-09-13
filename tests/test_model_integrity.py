import hashlib
from modules.model_manager import verify_model_integrity

def test_streaming_model_hash_check(tmp_path):
    model=tmp_path/'model.bin'; model.write_bytes(b'model-bytes')
    assert verify_model_integrity(str(model),hashlib.sha256(b'model-bytes').hexdigest())
