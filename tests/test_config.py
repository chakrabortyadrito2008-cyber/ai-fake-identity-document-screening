from pathlib import Path
from core.config import load_settings

def test_settings_are_validated():
    settings=load_settings(Path(__file__).parents[1])
    assert settings['risk']['review_threshold'] < settings['risk']['high_threshold']
