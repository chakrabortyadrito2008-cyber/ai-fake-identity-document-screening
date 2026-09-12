from modules.trusted_source import LocalSyntheticSource
def test_synthetic_source(): assert LocalSyntheticSource({'x':{}}).lookup('x')=={}
