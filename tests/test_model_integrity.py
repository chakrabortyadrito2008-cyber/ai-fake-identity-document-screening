import hashlib
from modules.model_integrity import ModelIntegrity

def test_streaming_model_hash_check(tmp_path):
    model=tmp_path/'model.bin'; model.write_bytes(b'model-bytes')
    assert ModelIntegrity.verify(str(model),hashlib.sha256(b'model-bytes').hexdigest())
