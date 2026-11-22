"""Make scripts/ importable in tests. Every test uses synthetic data made at run time."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
