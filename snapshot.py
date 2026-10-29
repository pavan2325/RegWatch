import winreg
from config import MONITORED_KEYS, HIVE_NAMES

TYPE_NAMES = {
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
}


def _serialize(data):
    """Make registry data safe to store as JSON."""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        return list(data)
    return data


def read_key(hive, path):
    """Return {'exists': bool, 'error': str or None, 'values': {...}}."""
    result = {"exists": False, "error": None, "values": {}}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            result["exists"] = True
            i = 0
            while True:
                try:
                    name, data, typ = winreg.EnumValue(key, i)
                    result["values"][name or "(Default)"] = {
                        "data": _serialize(data),
                        "type": TYPE_NAMES.get(typ, str(typ)),
                    }
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass  # key does not exist (normal for many security keys)
    except PermissionError:
        result["error"] = "access_denied"
    return result


def take_snapshot():
    """Read every monitored key and return one dictionary."""
    snapshot = {}
    for entry in MONITORED_KEYS:
        full_path = f"{HIVE_NAMES[entry['hive']]}\\{entry['path']}"
        data = read_key(entry["hive"], entry["path"])
        data["category"] = entry["category"]
        snapshot[full_path] = data
    return snapshot


if __name__ == "__main__":
    import json
    print(json.dumps(take_snapshot(), indent=2))