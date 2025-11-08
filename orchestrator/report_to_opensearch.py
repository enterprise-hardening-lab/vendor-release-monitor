import os
import json
import requests
from datetime import datetime
from pathlib import Path

def push_to_opensearch():
    """Push weekly CVE summary to OpenSearch/ELK for dashboards."""
    report_file = Path("reports/weekly_cve_summary.json")
    if not report_file.exists():
        print("❌ weekly_cve_summary.json not found.")
        return

    data = json.loads(report_file.read_text())
    opensearch_url = os.getenv("OPENSEARCH_URL")
    opensearch_index = os.getenv("OPENSEARCH_INDEX", "vendor-cve-summary")
    auth_user = os.getenv("OPENSEARCH_USER")
    auth_pass = os.getenv("OPENSEARCH_PASS")

    if not opensearch_url:
        print("⚠️ OPENSEARCH_URL not configured — skipping upload.")
        return

    index_url = f"{opensearch_url}/{opensearch_index}/_doc"
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "week_start": data["week_start"],
        "week_end": data["week_end"],
        "vendors": data["vendors"],
        "total": data["total"]
    }

    try:
        resp = requests.post(index_url, json=payload, auth=(auth_user, auth_pass), timeout=15)
        resp.raise_for_status()
        print(f"✅ Summary pushed to OpenSearch index '{opensearch_index}' ({resp.status_code})")
    except Exception as e:
        print(f"❌ Failed to push summary to OpenSearch: {e}")


if __name__ == "__main__":
    push_to_opensearch()
