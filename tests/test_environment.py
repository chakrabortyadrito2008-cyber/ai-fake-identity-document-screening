import os
from core.config import load_local_env

def test_local_env_does_not_override_real_environment(tmp_path, monkeypatch):
    file=tmp_path/'.env'; file.write_text('FRAUD_TEST_VALUE=file-value\n')
    monkeypatch.setenv('FRAUD_TEST_VALUE','real-value')
    load_local_env(file)
    assert os.environ['FRAUD_TEST_VALUE']=='real-value'
