import os
import re

SUSPICIOUS_DIRS = ["\\appdata\\", "\\temp\\", "\\downloads\\",
                   "\\users\\public\\", "\\programdata\\"]
TRUSTED_PATHS = ["\\microsoft\\teams\\", "\\microsoft\\onedrive\\",
                 "\\discord\\", "\\microsoft\\edge\\"]
                 

DEFENDER_DISABLE_VALUES = {
    "disableantispyware", "disableantivirus", "disablerealtimemonitoring",
    "disablebehaviormonitoring", "disableioavprotection", "disableonaccessprotection",
}

NORMAL_SHELL = "explorer.exe"
NORMAL_USERINIT = "c:\\windows\\system32\\userinit.exe"


def _result(severity, rule, message):
    return {"severity": severity, "rule": rule, "message": message}


def _norm(value):
    return str(value).strip().rstrip(",").lower()


def extract_exe(data):
    """Pull the program path out of an autorun value."""
    text = os.path.expandvars(str(data)).strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end != -1 else text[1:]
    match = re.search(r"^(.*?\.(exe|bat|cmd|vbs|ps1|js|dll|scr))", text, re.IGNORECASE)
    return match.group(1) if match else text


def analyze(change):
    """Return {'severity', 'rule', 'message'} for one detected change."""
    cat = change["category"]
    ctype = change["type"]
    name = change["value_name"] or ""
    lname = name.lower()
    new = change["new"]["data"] if change["new"] else None
    key = change["key"]

    if cat == "Test":
        return _result("Info", "Test key change", f"{ctype} on test key: {key}")

    # Whole-key changes (no value involved)
    if change["value_name"] is None:
        if cat == "UAC Bypass" and ctype == "KEY_ADDED":
            return _result("High", "UAC bypass key created",
                           f"UAC bypass-related key created: {key}")
        return _result("Low", "Key structure change", f"{ctype}: {key}")

    # Autorun / persistence
    if cat == "Autorun":
        if ctype in ("ADDED", "MODIFIED"):
            exe = extract_exe(new)
            label = "New" if ctype == "ADDED" else "Modified"
            low = exe.lower()
            trusted = any(t in low for t in TRUSTED_PATHS)
            if any(d in low for d in SUSPICIOUS_DIRS) and not trusted:
                return _result("High", "Autorun from suspicious location",
                               f"{label} autorun entry detected: {exe}")
            return _result("Medium", "New autorun entry",
                           f"{label} autorun entry detected: {exe}")
        return _result("Low", "Autorun entry removed", f"Autorun entry removed: {name}")

    # Security tools (Defender / Firewall)
    if cat == "Security" and ctype in ("ADDED", "MODIFIED"):
        if lname in DEFENDER_DISABLE_VALUES and new == 1:
            return _result("High", "Defender disabled",
                           f"Registry key altered: Windows Defender disabled ({name}=1)")
        if lname == "enablefirewall" and new == 0:
            return _result("High", "Firewall disabled",
                           "Registry key altered: Windows Firewall disabled (EnableFirewall=0)")
        return _result("Medium", "Security setting changed", f"Security value changed: {name}")

    # Shell replacement
    if cat == "Shell" and ctype in ("ADDED", "MODIFIED"):
        if lname == "shell" and _norm(new) != NORMAL_SHELL:
            return _result("High", "Shell replacement",
                           f"Windows shell replaced with: {new}")
        if lname == "userinit" and _norm(new) != NORMAL_USERINIT:
            return _result("High", "Userinit modified", f"Userinit altered: {new}")
        return _result("Low", "Winlogon value changed", f"Winlogon value changed: {name}")

    # UAC
    if cat == "UAC" and ctype in ("ADDED", "MODIFIED"):
        if lname == "enablelua" and new == 0:
            return _result("High", "UAC disabled", "Registry key altered: UAC disabled (EnableLUA=0)")
        if lname in ("consentpromptbehavioradmin", "promptonsecuredesktop") and new == 0:
            return _result("Medium", "UAC weakened", f"UAC prompt weakened: {name}=0")
        return _result("Low", "UAC setting changed", f"UAC value changed: {name}")

    # UAC bypass hijack
    if cat == "UAC Bypass" and ctype in ("ADDED", "MODIFIED"):
        return _result("High", "UAC bypass hijack",
                       f"UAC bypass command set: {new}")

    return _result("Low", "Other change", f"{ctype}: {key} -> {name}")