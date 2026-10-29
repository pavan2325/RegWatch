import winreg
from config import MONITORED_KEYS, HIVE_NAMES
from test_read import read_key, TYPE_NAMES

for entry in MONITORED_KEYS:
    hive_name = HIVE_NAMES[entry["hive"]]
    print(f"\n[{entry['category']}] {hive_name}\\{entry['path']}")
    values = read_key(entry["hive"], entry["path"])
    if not values:
        print("   (no values)")
    for name, (data, typ) in values.items():
        shown = str(data)[:80]
        print(f"   {name or '(Default)'} = {shown}  [{TYPE_NAMES.get(typ, typ)}]")