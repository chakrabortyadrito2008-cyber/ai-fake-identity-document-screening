from pathlib import Path
from modules.trusted_source import LocalSyntheticSource

def test_synthetic_record_is_loaded():
    source=LocalSyntheticSource.from_json(Path(__file__).parents[1]/'data/synthetic_data/identities.json')
    assert source.lookup('synthetic-legitimate-001')['status']=='CONFIRMED_LEGITIMATE'
