import json
import hashlib
import os
from datetime import datetime

BASELINE_FILE = "data/baseline.json"
HASH_FILE = "data/baseline.sha256"


def save_baseline(snapshot):
    os.makedirs("data", exist_ok=True)
    payload = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "snapshot": snapshot,
    }
    raw = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

    with open(BASELINE_FILE, "wb") as f:
        f.write(raw)

    digest = hashlib.sha256(raw).hexdigest()
    with open(HASH_FILE, "w") as f:
        f.write(digest)
    return digest


def load_baseline():
    """Return (payload, is_intact) or None if no baseline exists."""
    if not os.path.exists(BASELINE_FILE) or not os.path.exists(HASH_FILE):
        return None

    with open(BASELINE_FILE, "rb") as f:
        raw = f.read()
    with open(HASH_FILE) as f:
        stored_digest = f.read().strip()

    is_intact = hashlib.sha256(raw).hexdigest() == stored_digest
    return json.loads(raw.decode("utf-8")), is_intact