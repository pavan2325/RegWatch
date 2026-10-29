import winreg

TYPE_NAMES = {
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
}

def read_key(hive, path):
    values = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, typ = winreg.EnumValue(key, i)
                    values[name] = (data, typ)
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        print(f"Key not found: {path}")
    except PermissionError:
        print(f"Access denied: {path}")
    return values

if __name__ == "__main__":
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    result = read_key(winreg.HKEY_CURRENT_USER, path)
    for name, (data, typ) in result.items():
        print(f"{name or '(Default)'} = {data}  [{TYPE_NAMES.get(typ, typ)}]")