import requests
import xml.etree.ElementTree as ET
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

    versions = []
    for _, product_data in products.items():
        version = product_data.get("version")
        if version and "LTS" in product_data.get("release_title", ""):
            versions.append((version, product_data.get("release_title")))

    if not versions:
        print("❌ No LTS versions found in stream data.")
        return None

    latest_version = sorted(versions, key=lambda x: x[0], reverse=True)[0][1]
    print(f"✅ Latest Ubuntu version detected: {latest_version}")
    return latest_version


def get_latest_cves(stream="24.04-lts", days=7):
    """
    Fetch Ubuntu CVEs from the official Ubuntu Security RSS feed.
    Source: https://ubuntu.com/security/notices/rss.xml
    """
    try:
        url = "https://ubuntu.com/security/notices/rss.xml"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()

        root = ET.fromstring(resp.content)
        items = root.findall(".//item")
        cutoff = datetime.utcnow() - timedelta(days=days)
        results = []

        for item in items:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            pub_date_str = item.findtext("pubDate", "")
            try:
                pub_date = datetime.strptime(pub_date_str, "%a, %d %b %Y %H:%M:%S %Z")
            except Exception:
                continue

            if pub_date < cutoff:
                continue

            cve_ids = [word for word in title.split() if word.startswith("CVE-")]
            if not cve_ids:
                continue

            for cve_id in cve_ids:
                results.append({
                    "vendor": "ubuntu",
                    "stream": stream,
                    "cve_id": cve_id,
                    "description": title,
                    "severity": "High",
                    "cvss_score": 0.0,
                    "status": "open",
                    "published_at": pub_date.isoformat() + "Z",
                    "updated_at": pub_date.isoformat() + "Z",
                    "package": "",
                    "fixed_version": "",
                    "references": [link],
                    "source": "ubuntu",
                    "fetched_at": datetime.utcnow().isoformat() + "Z"
                })

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
