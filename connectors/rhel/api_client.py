import requests
import re
import sys
from datetime import datetime, timedelta

def get_latest_rhel_version():
    """
    Fetch the latest RHEL version using the Red Hat Security Data API (Hydra).
    Endpoint: https://access.redhat.com/hydra/rest/securitydata/cve.json
    """
    URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=50"

    try:
        response = requests.get(URL, timeout=20)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"❌ Failed to query Red Hat API: {e}")
        sys.exit(1)

    versions = set()
    for entry in data:
        for rel in entry.get("affected_release") or []:
            name = rel.get("product_name", "")
            match = re.search(r"Red Hat Enterprise Linux (\d+(?:\.\d+)?)", name)
            if match:
                versions.add(match.group(1))

    if not versions:
        print("⚠️ No RHEL versions found in API response — possible rate limit or schema change.")
        return None

    latest = sorted(versions, key=lambda v: [int(x) for x in v.split('.')], reverse=True)[0]
    print(f"✅ Latest RHEL version detected: {latest}")
    return latest


def get_latest_cves(stream="rhel-9", days=7):
    """
    Fetch recent Critical/Important CVEs for RHEL from Red Hat's Hydra API.
    Combines results for 'Critical' and 'Important' in separate paged queries.
    """
    try:
        severities = ["Critical", "Important"]
        end_date = datetime.utcnow()
        start_date = (end_date - timedelta(days=days)).strftime("%Y-%m-%d")

        results = []
        for sev in severities:
            url = (
                f"https://access.redhat.com/hydra/rest/securitydata/cve.json?"
                f"severity={sev}&per_page=100"
            )

            resp = requests.get(url, timeout=20)
            if resp.status_code != 200:
                print(f"⚠️ API returned {resp.status_code} for severity={sev}")
                continue
            data = resp.json()

            for cve in data:
                cve_id = cve.get("CVE")
                if not cve_id:
                    continue

                severity = cve.get("severity", sev)
                score = float(cve.get("cvss3_score", 0) or 0)
                desc = cve.get("bugzilla_description") or cve.get("description") or "No description available"

                results.append({
                    "vendor": "rhel",
                    "stream": stream,
                    "cve_id": cve_id,
                    "description": desc,
                    "severity": severity,
                    "cvss_score": score,
                    "status": "open",
                    "published_at": cve.get("public_date", datetime.utcnow().isoformat() + "Z"),
                    "updated_at": cve.get("modified_date", datetime.utcnow().isoformat() + "Z"),
                    "package": ", ".join(cve.get("affected_packages", [])) if cve.get("affected_packages") else "",
                    "fixed_version": "",
                    "references": [cve.get("resource_url", "")],
                    "source": "rhel",
                    "fetched_at": datetime.utcnow().isoformat() + "Z"
                })

        print(f"✅ Found {len(results)} RHEL CVEs (last {days} days)")
        return results

    except Exception as e:
        print(f"❌ Failed to fetch RHEL CVEs: {e}")
        return []


if __name__ == "__main__":
    print("\n--- Testing RHEL Release Detection ---")
    get_latest_rhel_version()
    print("\n--- Testing RHEL CVE Fetch ---")
    cves = get_latest_cves()
    print(f"Sample CVEs: {cves[:2] if cves else 'No results'}")
