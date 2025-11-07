import json
import sys
from pathlib import Path

def compare_versions(vendor, new_version):
    """
    Compare the new detected version with the last stored one.
    Update catalog/state/{vendor}.json if newer version is found.
    """
    state_file = Path(f"catalog/state/{vendor}.json")

    if not state_file.exists():
        print(f"⚠️ State file not found for {vendor}, creating new one.")
        last_version = None
        state_file.write_text(json.dumps({"vendor": vendor, "last_version": new_version}, indent=2))
        return

    data = json.loads(state_file.read_text())
    last_version = data.get("last_version")

    if last_version == new_version:
        print(f"✅ No new release for {vendor}. Catalog up to date ({last_version}).")
    else:
        print(f"🆕 New release detected for {vendor}: {new_version} (previous: {last_version})")
        data["last_version"] = new_version
        state_file.write_text(json.dumps(data, indent=2))
        print(f"✅ Catalog updated for {vendor}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/compare_versions.py <vendor> <version>")
        sys.exit(1)
    compare_versions(sys.argv[1], sys.argv[2])
