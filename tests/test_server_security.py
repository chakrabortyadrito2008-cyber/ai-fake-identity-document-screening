import subprocess
import sys
from pathlib import Path


def test_cli_refuses_public_binding_without_api_key():
    root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "main.py", "serve", "--host", "0.0.0.0"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "Refusing non-localhost binding" in result.stderr
