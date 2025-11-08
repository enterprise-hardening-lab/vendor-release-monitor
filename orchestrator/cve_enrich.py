import os
import sys
import json
from pathlib import Path
from datetime import datetime
from importlib import import_module

from orchestrator.emit import emit_cve_event
from orchestrator.normalize import validate_json


def get_connector(vendor):
    """
    Dynamically import the connector module for the vendor.
    """
    connector_map = {
        "ubuntu": "connectors.ubuntu.rss_fetcher",
        "rhel": "connectors.rhel.api_client",
        "amazonlinux": "connectors.amazonlinux.rss_feed",
    }

    if vendor not in connector_map:
        raise ValueError(f"Unsupported vendor: {vendor}")

    module_name = connector_map[vendor]
    module = import_module(module_name)
    return module


def load_policy():
    """
    Load CVE policy settings (severity, retention, etc.)
    """
    try:
        policy = json.loads(
            Path("rules/policy.yaml").read_text()
            .replace(": true", ": True")
            .replace(": false", ": False")
            .replace("'", "\"")
        )
        return policy.get("cve_policy", {})
    except Exception as e:
        print(f"⚠️ Failed to load policy.yaml: {e}")
        return {
            "alert_severity": ["Critical", "High"],
            "minimum_cvss_score": 7.0,
        }


def ensure_output_dir(vendor, stream):
    """
    Ensure catalog/cves/<vendor>/<stream>/ exists.
    """
    path = Path(f"catalog/cves/{vendor}/{stream}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_cve_json(vendor, stream, data):
    """
    Save normalized CVE records for this vendor/stream/date.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    path = ensure_output_dir(vendor, stream) / f"{today}.json"
    path.write_text(json.dumps(data, indent=2))
    print(f"📦 Saved CVE report: {path}")
    return path


def filter_cves_by_policy(cves, policy):
    """
    Apply policy thresholds (severity + CVSS score).
    """
    filtered = []
    for cve in cves:
        severity = cve.get("severity", "")
        score = float(cve.get("cvss_score", 0.0))
        if severity in policy.get("alert_severity", []) or score >= policy.get("minimum_cvss_score", 7.0):
            filtered.append(cve)
    print(f"🧩 {len(filtered)}/{len(cves)} CVEs meet policy criteria")
    return filtered


def main(vendor):
    print(f"🚀 Starting CVE enrichment for vendor: {vendor}")
    connector = get_connector(vendor)
    policy = load_policy()

    # For now, use default stream from rules/streams.yaml naming
    stream_map = {"ubuntu": "24.04-lts", "rhel": "rhel-9", "amazonlinux": "al2023"}
    stream = stream_map.get(vendor, "unknown")

    # Fetch CVEs via connector
    if hasattr(connector, "get_latest_cves"):
        cves = connector.get_latest_cves(stream)
    else:
        print(f"❌ Connector for {vendor} missing get_latest_cves()")
        return

    if not cves:
        print(f"ℹ️ No CVEs detected for {vendor}")
        return

    # Apply policy filter
    filtered = filter_cves_by_policy(cves, policy)

    # Save results
    json_path = save_cve_json(vendor, stream, filtered)

    # Validate JSON output against schema
    validate_json(str(json_path), "schemas/cve.schema.json")

    # Emit GitHub Issues for each CVE
    for cve in filtered:
        emit_cve_event(
            vendor=vendor,
            stream=stream,
            cve_id=cve["cve_id"],
            severity=cve["severity"],
            score=float(cve["cvss_score"]),
            status=cve["status"]
        )

    print(f"✅ CVE enrichment completed for {vendor}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 orchestrator/cve_enrich.py <vendor>")
        sys.exit(1)

    vendor = sys.argv[1].lower()
    main(vendor)
