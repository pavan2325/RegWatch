import json
import os
import subprocess
from datetime import datetime

from snapshot import take_snapshot
from compare import compare
from patterns import analyze

ROOT = r"HKCU\Software\RegWatchTest"
SUBKEYS = ["Run", "Security", "Winlogon", "Policies", "UACBypass"]
RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}

# (name, kind, subkey, value name (None = default), type, data, expected)
SCENARIOS = [
    # Attacks that should reach High
    ("Autorun from Public folder", "attack", "Run", "Updater", "REG_SZ", r"C:\Users\Public\fake.exe", "High"),
    ("Autorun from AppData with arguments", "attack", "Run", "Helper", "REG_SZ", r"C:\Users\Test\AppData\Roaming\svc.exe /s", "High"),
    ("Defender disabled", "attack", "Security", "DisableAntiSpyware", "REG_DWORD", "1", "High"),
    ("Real-time protection off", "attack", "Security", "DisableRealtimeMonitoring", "REG_DWORD", "1", "High"),
    ("Firewall disabled", "attack", "Security", "EnableFirewall", "REG_DWORD", "0", "High"),
    ("Shell replaced", "attack", "Winlogon", "Shell", "REG_SZ", r"C:\Users\Public\evil.exe", "High"),
    ("Userinit hijacked", "attack", "Winlogon", "Userinit", "REG_SZ", r"C:\Windows\System32\userinit.exe,C:\Users\Public\evil.exe", "High"),
    ("UAC disabled", "attack", "Policies", "EnableLUA", "REG_DWORD", "0", "High"),
    ("UAC bypass hijack", "attack", "UACBypass", None, "REG_SZ", r"C:\Users\Public\fake.exe", "High"),
    # Attacks the rules may miss (known weaknesses)
    ("Autorun from non-standard folder", "attack", "Run", "Backup", "REG_SZ", r"C:\Tools\evil.exe", "High"),
    ("Defender: different value name", "attack", "Security", "DisableRoutinelyTakingAction", "REG_DWORD", "1", "High"),
    # Benign changes that should NOT reach High
    ("Normal shell value", "benign", "Winlogon", "Shell", "REG_SZ", "explorer.exe", "NotHigh"),
    ("UAC left enabled", "benign", "Policies", "EnableLUA", "REG_DWORD", "1", "NotHigh"),
    ("Defender setting turned on", "benign", "Security", "DisableAntiSpyware", "REG_DWORD", "0", "NotHigh"),
    ("Autorun from Program Files", "benign", "Run", "ChatApp", "REG_SZ", r"C:\Program Files\App\app.exe", "NotHigh"),
    ("Legitimate Teams autorun (AppData)", "benign", "Run", "Teams", "REG_SZ", r"C:\Users\Test\AppData\Local\Microsoft\Teams\Update.exe", "NotHigh"),
]


def reg(*args):
    return subprocess.run(["reg", *args], capture_output=True, text=True)


def reset_test_keys():
    reg("delete", ROOT, "/f")
    reg("add", ROOT, "/f")
    for sub in SUBKEYS:
        reg("add", f"{ROOT}\\{sub}", "/f")


def apply(sub, name, typ, data):
    key = f"{ROOT}\\{sub}"
    if name is None:
        reg("add", key, "/ve", "/t", typ, "/d", data, "/f")
    else:
        reg("add", key, "/v", name, "/t", typ, "/d", data, "/f")


def revert(sub, name):
    key = f"{ROOT}\\{sub}"
    if name is None:
        reg("delete", key, "/ve", "/f")
    else:
        reg("delete", key, "/v", name, "/f")


def run():
    reset_test_keys()
    baseline = take_snapshot()
    results = []

    print(f"{'#':>2}  {'Scenario':38} {'Type':7} {'Expected':8} {'Got':7} Outcome")
    print("-" * 78)

    for i, (name, kind, sub, vname, typ, data, expected) in enumerate(SCENARIOS, 1):
        apply(sub, vname, typ, data)
        full_key = f"HKCU\\Software\\RegWatchTest\\{sub}"
        changes = [c for c in compare(baseline, take_snapshot()) if c["key"] == full_key]
        findings = [analyze(c) for c in changes]
        revert(sub, vname)

        if findings:
            got = max(findings, key=lambda f: RANK[f["severity"]])["severity"]
        else:
            got = "None"
        is_high = got == "High"

        if kind == "attack":
            outcome = "TP" if is_high else "FN"
        else:
            outcome = "FP" if is_high else "TN"

        results.append({"name": name, "kind": kind, "expected": expected,
                        "got": got, "outcome": outcome})
        print(f"{i:>2}  {name:38} {kind:7} {expected:8} {got:7} {outcome}")

    tp = sum(r["outcome"] == "TP" for r in results)
    fn = sum(r["outcome"] == "FN" for r in results)
    tn = sum(r["outcome"] == "TN" for r in results)
    fp = sum(r["outcome"] == "FP" for r in results)
    total = len(results)

    metrics = {
        "Total scenarios": total,
        "True Positives (attacks caught)": tp,
        "False Negatives (attacks missed)": fn,
        "True Negatives (benign allowed)": tn,
        "False Positives (benign flagged High)": fp,
        "Accuracy": f"{(tp + tn) / total * 100:.1f}%",
        "Detection rate (attacks caught)": f"{tp / (tp + fn) * 100:.1f}%" if tp + fn else "n/a",
        "False positive rate": f"{fp / (fp + tn) * 100:.1f}%" if fp + tn else "n/a",
    }

    print("\n=== Detection Summary ===")
    for k, v in metrics.items():
        print(f"  {k:40} {v}")

    os.makedirs("logs", exist_ok=True)
    with open("logs/test_results.json", "w", encoding="utf-8") as f:
        json.dump({"generated": datetime.now().isoformat(timespec="seconds"),
                   "metrics": metrics, "results": results}, f, indent=2)
    print("\nSaved: logs/test_results.json")


if __name__ == "__main__":
    run()