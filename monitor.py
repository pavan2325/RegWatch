import time
from datetime import datetime

from snapshot import take_snapshot
from baseline import load_baseline
from compare import compare
from patterns import analyze
from alerts import raise_alert


def change_id(c):
    return (c["type"], c["key"], c["value_name"], str(c["new"]))


def run_monitor(interval=10):
    loaded = load_baseline()
    if loaded is None:
        print("No baseline found. Run: python main.py --baseline")
        return 1
    payload, intact = loaded
    if not intact:
        print("Baseline file has been tampered with. Monitoring aborted.")
        return 2

    baseline = payload["snapshot"]
    seen = set()
    cycle = 0
    print(f"Monitoring started (every {interval}s). Press Ctrl+C to stop.\n")

    try:
        while True:
            cycle += 1
            changes = compare(baseline, take_snapshot())
            current = {change_id(c): c for c in changes}
            new_ids = [cid for cid in current if cid not in seen]

            for cid in new_ids:
                raise_alert(current[cid], analyze(current[cid]))

            print(f"[{datetime.now():%H:%M:%S}] check #{cycle}: {len(new_ids)} new change(s)")
            seen = set(current)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
    return 0