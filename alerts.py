import json
import os
from datetime import datetime

ALERT_LOG = "logs/alerts.log"
COLORS = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[96m", "Info": "\033[90m"}
RESET = "\033[0m"

os.system("")  # enables colors in older Windows terminals


def _data(entry):
    return entry["data"] if entry else None


def raise_alert(change, finding):
    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": finding["severity"],
        "rule": finding["rule"],
        "message": finding["message"],
        "category": change["category"],
        "change_type": change["type"],
        "key": change["key"],
        "value_name": change["value_name"],
        "old": _data(change["old"]),
        "new": _data(change["new"]),
    }

    os.makedirs("logs", exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    color = COLORS.get(record["severity"], "")
    print(f"{color}[{record['severity'].upper()}] {record['timestamp']}  {record['rule']}{RESET}")
    print(f"   {record['message']}")
    print(f"   Key: {record['key']}")
    if record["value_name"]:
        print(f"   Value: {record['value_name']}   old: {record['old']}   new: {record['new']}")
    print()
    return record