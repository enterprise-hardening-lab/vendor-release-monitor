import json
from pathlib import Path
from scripts.compare_versions import compare_versions

def get_release_version(vendor: str) -> str:
    """
    Extract the release version from catalog/state/<vendor>.json.
    Handles both legacy 'last_version' and new 'release.version' fields.
    """
    file_path = Path(f"catalog/state/{vendor}.json")

    if not file_path.exists():
        print(f"⚠️ State file missing for {vendor}.")
        return None

    data = json.loads(file_path.read_text())

    # backward compatibility
    if "last_version" in data:
        return data["last_version"]

    # new structure support
    if "release" in data and "version" in data["release"]:
        return data["release"]["version"]

    print(f"⚠️ No version found in {vendor} state file.")
    return None


def compare_normalized(vendor: str, new_version: str):
    """
    Wrapper around the legacy compare_versions to provide normalized comparison.
    It reads existing version, compares, updates if necessary.
    """
    current_version = get_release_version(vendor)

    if current_version == new_version:
        print(f"✅ {vendor} already up to date: {current_version}")
    else:
        print(f"🆕 Detected version change for {vendor}: {current_version} → {new_version}")
        compare_versions(vendor, new_version)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 orchestrator/compare.py <vendor> <new_version>")
        sys.exit(1)

    vendor = sys.argv[1]
    new_version = sys.argv[2]
    compare_normalized(vendor, new_version)
