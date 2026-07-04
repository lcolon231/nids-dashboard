import sys
from pathlib import Path

# Make nids_sensor importable when running `pytest` from sensor/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
