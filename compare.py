EMPTY = {"exists": False, "values": {}}


def compare(baseline, current):
    """Return a list of changes between two snapshots."""
    changes = []

    for key_path in sorted(set(baseline) | set(current)):
        b = baseline.get(key_path, EMPTY)
        c = current.get(key_path, EMPTY)
        category = c.get("category") or b.get("category", "Unknown")

        if not b["exists"] and c["exists"]:
            changes.append({"type": "KEY_ADDED", "key": key_path, "value_name": None,
                            "old": None, "new": None, "category": category})
        elif b["exists"] and not c["exists"]:
            changes.append({"type": "KEY_DELETED", "key": key_path, "value_name": None,
                            "old": None, "new": None, "category": category})

        old_values = b["values"]
        new_values = c["values"]

        for name in sorted(set(old_values) | set(new_values)):
            if name not in old_values:
                change_type = "ADDED"
            elif name not in new_values:
                change_type = "DELETED"
            elif old_values[name] != new_values[name]:
                change_type = "MODIFIED"
            else:
                continue

            changes.append({
                "type": change_type,
                "key": key_path,
                "value_name": name,
                "old": old_values.get(name),
                "new": new_values.get(name),
                "category": category,
            })

    return changes