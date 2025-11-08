import json
import sys
from pathlib import Path
from jsonschema import validate, ValidationError

def validate_json(data_path: str, schema_path: str):
    """Validate a JSON file against a JSON schema."""
    schema = json.loads(Path(schema_path).read_text())
    data = json.loads(Path(data_path).read_text())

    try:
        validate(instance=data, schema=schema)
        print(f"✅ Validation passed for {data_path} against {schema_path}")
        return True
    except ValidationError as e:
        print(f"❌ Validation failed for {data_path}")
        print(f"Reason: {e.message}")
        return False


def normalize_release(vendor: str):
    """
    Validate and normalize vendor release data.
    Connectors output JSON → validated against schemas/release.schema.json
    """
    data_file = f"catalog/state/{vendor}.json"
    schema_file = "schemas/release.schema.json"

    if not Path(data_file).exists():
        print(f"⚠️ {data_file} not found — skipping normalization.")
        return

    print(f"🔍 Validating {vendor} release data...")
    validate_json(data_file, schema_file)


def normalize_cve(vendor: str, stream: str, date_str: str):
    """
    Validate vendor CVE report JSON.
    Example file path: catalog/cves/<vendor>/<stream>/<date>.json
    """
    data_file = f"catalog/cves/{vendor}/{stream}/{date_str}.json"
    schema_file = "schemas/cve.schema.json"

    if not Path(data_file).exists():
        print(f"⚠️ {data_file} not found — skipping CVE normalization.")
        return

    print(f"🔍 Validating CVE data for {vendor}:{stream} ({date_str})")
    validate_json(data_file, schema_file)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 orchestrator/normalize.py <type> <vendor> [stream] [date]")
        sys.exit(1)

    mode = sys.argv[1]
    vendor = sys.argv[2]

    if mode == "release":
        normalize_release(vendor)
    elif mode == "cve":
        if len(sys.argv) != 5:
            print("Usage for CVE mode: python3 orchestrator/normalize.py cve <vendor> <stream> <date>")
            sys.exit(1)
        normalize_cve(vendor, sys.argv[3], sys.argv[4])
    else:
        print(f"❌ Unknown mode: {mode}")
        sys.exit(1)
