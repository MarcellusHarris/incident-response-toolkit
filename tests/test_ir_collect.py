import subprocess
import sys


def test_help_flag():
    result = subprocess.run([sys.executable, "ir_collect.py", "--help"], capture_output=True, text=True)
    assert result.returncode == 0


def test_modules_flag():
    result = subprocess.run([sys.executable, "ir_collect.py", "--modules", "processes"], capture_output=True, text=True)
    assert result.returncode == 0
