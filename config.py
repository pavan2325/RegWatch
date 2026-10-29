import winreg

HKCU = winreg.HKEY_CURRENT_USER
HKLM = winreg.HKEY_LOCAL_MACHINE

HIVE_NAMES = {HKCU: "HKCU", HKLM: "HKLM"}

MONITORED_KEYS = [
    # Autorun (persistence)
    {"hive": HKCU, "path": r"Software\Microsoft\Windows\CurrentVersion\Run", "category": "Autorun"},
    {"hive": HKCU, "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "category": "Autorun"},
    {"hive": HKLM, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "category": "Autorun"},
    {"hive": HKLM, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "category": "Autorun"},

    # Security tools (Defender / Firewall)
    {"hive": HKLM, "path": r"SOFTWARE\Policies\Microsoft\Windows Defender", "category": "Security"},
    {"hive": HKLM, "path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "category": "Security"},
    {"hive": HKLM, "path": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile", "category": "Security"},

    # Shell replacement
    {"hive": HKLM, "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "category": "Shell"},

    # UAC
    {"hive": HKLM, "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "category": "UAC"},
    {"hive": HKCU, "path": r"Software\Classes\ms-settings\Shell\Open\command", "category": "UAC Bypass"},

    # Safe test key (use this for all simulations)
    {"hive": HKCU, "path": r"Software\RegWatchTest", "category": "Test"},
]
