import argparse
import os
from collections import Counter
from datetime import datetime

from snapshot import take_snapshot
from baseline import save_baseline, load_baseline
from compare import compare
from patterns import analyze
from alerts import raise_alert
from monitor import run_monitor
from report import build_report


def show(value):
    if value is None:
        return "(none)"
    return f"{value['data']} [{value['type']}]"


def write_log(line):
    os.makedirs("logs", exist_ok=True)
    with open("logs/integrity_check.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def cmd_baseline():
    snapshot = take_snapshot()
    digest = save_baseline(snapshot)
    found = sum(1 for k in snapshot.values() if k["exists"])
    total_values = sum(len(k["values"]) for k in snapshot.values())
    print("Baseline created.")
    print(f"  Keys monitored : {len(snapshot)} ({found} exist on this system)")
    print(f"  Values captured: {total_values}")
    print(f"  SHA-256        : {digest}")
    write_log(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] BASELINE CREATED sha256={digest}")
    return 0


def cmd_check():
    loaded = load_baseline()
    if loaded is None:
        print("No baseline found. Run: python main.py --baseline")
        return 1

    payload, intact = loaded
    now = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
    print(f"Baseline created: {payload['created']}")

    if not intact:
        print("RESULT: FAIL - baseline file has been tampered with (checksum mismatch)")
        write_log(f"[{now}] INTEGRITY FAIL: baseline file tampered")
        return 2

    changes = compare(payload["snapshot"], take_snapshot())
    if not changes:
        print("RESULT: PASS - registry matches the baseline")
        write_log(f"[{now}] INTEGRITY PASS: no changes")
        return 0

    print(f"RESULT: FAIL - {len(changes)} change(s) detected\n")
    counts = Counter()
    for c in changes:
        finding = analyze(c)
        counts[finding["severity"]] += 1
        raise_alert(c, finding)
        write_log(f"[{now}] {finding['severity']} | {c['type']} | {c['category']} | "
                  f"{c['key']} | {c['value_name']} | old={show(c['old'])} | new={show(c['new'])}")

    print("Severity summary: " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    return 1


def main():
    parser = argparse.ArgumentParser(description="RegWatch registry monitoring toolkit")
    parser.add_argument("--baseline", action="store_true", help="capture a new baseline")
    parser.add_argument("--check", action="store_true", help="one-time integrity check")
    parser.add_argument("--monitor", action="store_true", help="live monitoring (polling)")
    parser.add_argument("--interval", type=int, default=10, help="seconds between checks")
    parser.add_argument("--report", action="store_true", help="generate the change-analysis report")
    args = parser.parse_args()

    if args.baseline:
        raise SystemExit(cmd_baseline())
    if args.check:
        raise SystemExit(cmd_check())
    if args.monitor:
        raise SystemExit(run_monitor(args.interval))
    if args.report:
        raise SystemExit(build_report())
    parser.print_help()


if __name__ == "__main__":
    main()