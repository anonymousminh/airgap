import os
from pathlib import Path

BASE_URL = os.environ.get("VULTR_BASE_URL", "https://api.vultrinference.com/v1")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
PLANNER_MODEL = os.environ.get("PLANNER_MODEL", "qwen3.8-27b")
EXPLAINER_MODEL = os.environ.get("EXPLAINER_MODEL", "glm-5.3")
RUNTIME = os.environ.get("SANDBOX_RUNTIME", "runsc")
STATE_DIR = Path(os.environ.get("AIRGAP_STATE_DIR", "/var/lib/airgap"))
UPLOAD_DIR = STATE_DIR / "uploads"
DB_PATH = STATE_DIR / "ledger.sqlite3"
KEY_PATH = STATE_DIR / "signing.key"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 200_000
SANDBOX_SLOTS = 2
RUNS_PER_WINDOW, ATTACKS_PER_WINDOW, WINDOW_S = 12, 36, 600
