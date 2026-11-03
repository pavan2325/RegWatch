import html
import json
import os
import re
from collections import Counter
from datetime import datetime

ALERT_LOG = "logs/alerts.log"
INTEGRITY_LOG = "logs/integrity_check.log"
TEST_RESULTS = "logs/test_results.json"
OUT_FILE = "reports/registry_report.html"
SEV_ORDER = ["High", "Medium", "Low", "Info"]

CSS = """
body{font-family:Arial,sans-serif;margin:40px;color:#1e293b}
h1{border-bottom:3px solid #2563eb;padding-bottom:8px}
h2{margin-top:32px;color:#1d4ed8}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
th{background:#2563eb;color:#fff;text-align:left;padding:8px}
td{border-bottom:1px solid #cbd5e1;padding:6px 8px}
tr:nth-child(even){background:#f1f5f9}
"""


def esc(x):
    return "" if x is None else html.escape(str(x))


def table(headers, rows):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def load_alerts():
    if not os.path.exists(ALERT_LOG):
        return []
    with open(ALERT_LOG, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def integrity_stats():
    stats = {"Baselines created": 0, "Clean checks (PASS)": 0,
             "Changes logged": 0, "Baseline tampering detected": 0}
    if os.path.exists(INTEGRITY_LOG):
        with open(INTEGRITY_LOG, encoding="utf-8") as f:
            for line in f:
                if "BASELINE CREATED" in line:
                    stats["Baselines created"] += 1
                elif "INTEGRITY PASS" in line:
                    stats["Clean checks (PASS)"] += 1
                elif "tampered" in line:
                    stats["Baseline tampering detected"] += 1
                elif re.search(r"\] (High|Medium|Low|Info) \|", line):
                    stats["Changes logged"] += 1
    return stats


def build_report():
    alerts = load_alerts()
    stats = integrity_stats()
    by_sev = Counter(a["severity"] for a in alerts)
    by_cat = Counter(a["category"] for a in alerts)
    by_rule = Counter(a["rule"] for a in alerts)
    autoruns = [a for a in alerts if a["category"] == "Autorun"]
    high = [a for a in alerts if a["severity"] == "High"]

    p = []
    p.append("<h1>RegWatch: Registry Change Analysis Report</h1>")
    p.append(f"<p>Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</p>")

    p.append("<h2>1. Summary</h2>")
    p.append(table(["Metric", "Value"],
                   [["Total alerts", len(alerts)]] +
                   [[f"{s} severity", by_sev.get(s, 0)] for s in SEV_ORDER]))

    p.append("<h2>2. Integrity Check Results</h2>")
    p.append(table(["Metric", "Value"], list(stats.items())))

    p.append("<h2>3. Alerts by Category</h2>")
    p.append(table(["Category", "Count"], by_cat.most_common()))

    p.append("<h2>4. Alerts by Detection Rule</h2>")
    p.append(table(["Rule", "Count"], by_rule.most_common()))

    p.append("<h2>5. Autorun Program Detections</h2>")
    p.append(table(["Time", "Severity", "Value", "Program", "Message"],
                   [[a["timestamp"], a["severity"], a["value_name"], a["new"], a["message"]]
                    for a in autoruns]) if autoruns else "<p>None detected.</p>")

    p.append("<h2>6. High-Severity Alerts</h2>")
    p.append(table(["Time", "Rule", "Key", "Value", "Old", "New"],
                   [[a["timestamp"], a["rule"], a["key"], a["value_name"], a["old"], a["new"]]
                    for a in high]) if high else "<p>None detected.</p>")

    p.append("<h2>7. Full Change Log</h2>")
    p.append(table(["Time", "Severity", "Type", "Key", "Value", "Old", "New"],
                   [[a["timestamp"], a["severity"], a["change_type"], a["key"],
                     a["value_name"], a["old"], a["new"]] for a in alerts[-200:]])
             if alerts else "<p>No alerts logged.</p>")

    if os.path.exists(TEST_RESULTS):
        with open(TEST_RESULTS, encoding="utf-8") as f:
            tr = json.load(f)
        p.append("<h2>8. Detection Test Results</h2>")
        p.append(table(["Metric", "Value"], list(tr["metrics"].items())))
        p.append(table(["Scenario", "Type", "Expected", "Got", "Outcome"],
                       [[r["name"], r["kind"], r["expected"], r["got"], r["outcome"]]
                        for r in tr["results"]]))

    os.makedirs("reports", exist_ok=True)
    page = f"<html><head><meta charset='utf-8'><title>RegWatch Report</title><style>{CSS}</style></head><body>{''.join(p)}</body></html>"
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(page)

    print("Report generated:", OUT_FILE)
    print(f"  Total alerts: {len(alerts)}  |  High: {by_sev.get('High', 0)}  "
          f"Medium: {by_sev.get('Medium', 0)}  Low: {by_sev.get('Low', 0)}")
    return 0