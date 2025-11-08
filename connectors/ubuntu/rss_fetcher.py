import requests
from datetime import datetime, timedelta

def get_latest_ubuntu_version():
    """
    Fetch the latest Ubuntu release version using the official JSON stream API.
    Source: https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:download.json
    """
    URL = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:download.json"
    response = requests.get(URL, timeout=10)
    response.raise_for_status()

    data = response.json()

    products = data.get("products", {})
    if not products:
        print("❌ Could not find products in Ubuntu release stream.")
        return None

    # Extract all versions and sort them
    versions = []
    for product_id, product_data in products.items():
        version = product_data.get("version")
        if version and "LTS" in product_data.get("release_title", ""):
            versions.append((version, product_data.get("release_title")))

    if not versions:
        print("❌ No LTS versions found in stream data.")
        return None

    # Sort versions lexicographically (e.g., 22.04.3 > 20.04.6)
    latest_version = sorted(versions, key=lambda x: x[0], reverse=True)[0][1]
    print(f"✅ Latest Ubuntu version detected: {latest_version}")
    return latest_version


def get_latest_cves(stream="24.04-lts", days=7):
    """
    Fetch the latest Ubuntu CVEs from the official Ubuntu Security API.
    Filters by 'High' or 'Critical' CVEs published in the last N days.
    Source: https://ubuntu.com/security/cve.json
    """
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        url = "https://ubuntu.com/security/cve.json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()

        data = resp.json()
        cves = data.get("cves", [])
        results = []

        for cve in cves:
            public_date_str = cve.get("public_date")
            if not public_date_str:
                continue

            # Parse and filter by recency
            try:
                public_date = datetime.strptime(public_date_str, "%Y-%m-%d")
            except ValueError:
                continue

            if public_date < start_date:
                continue

            severity = cve.get("priority", "").capitalize()
            if severity not in ["High", "Critical"]:
                continue

            cve_id = cve.get("id")
            if not cve_id:
                continue

            result = {
                "vendor": "ubuntu",
                "stream": stream,
                "cve_id": cve_id,
                "description": cve.get("description", "No description available"),
                "severity": severity,
                "cvss_score": cve.get("cvss_score", 0.0),
                "status": "open",
                "published_at": public_date.isoformat() + "Z",
                "updated_at": public_date.isoformat() + "Z",
                "package": cve.get("package", ""),
                "fixed_version": cve.get("patched_package", ""),
                "references": [f"https://ubuntu.com/security/{cve_id}"],
                "source": "ubuntu",
                "fetched_at": datetime.utcnow().isoformat() + "Z"
            }

            results.append(result)

        print(f"✅ Found {len(results)} new Ubuntu CVEs (last {days} days)")
        return results

    except Exception as e:
        print(f"❌ Failed to fetch Ubuntu CVEs: {e}")
        return []


if __name__ == "__main__":
    print("\n--- Testing Ubuntu Release Detection ---")
    get_latest_ubuntu_version()
    print("\n--- Testing Ubuntu CVE Fetch ---")
    cves = get_latest_cves()
    print(f"Sample CVEs: {cves[:2] if cves else 'No results'}")
