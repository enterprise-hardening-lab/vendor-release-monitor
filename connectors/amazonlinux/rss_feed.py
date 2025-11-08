import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

def get_latest_amazonlinux_version():
    """
    Fetch the latest Amazon Linux ALAS version from the official ALAS RSS feed.
    Source: https://alas.aws.amazon.com/alas.rss
    """
    URL = "https://alas.aws.amazon.com/alas.rss"

    try:
        resp = requests.get(URL, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"❌ Failed to fetch ALAS RSS feed: {e}")
        return None

    xml_root = ET.fromstring(resp.content)
    items = xml_root.findall(".//item")

    versions = set()
    for item in items:
        title = item.findtext("title", "")
        if "ALAS-" in title:
            parts = title.split()
            for p in parts:
                if p.startswith("ALAS-"):
                    versions.add(p)

    if not versions:
        print("⚠️ No Amazon Linux versions found in RSS feed.")
        return None

    latest = sorted(versions, reverse=True)[0]
    print(f"✅ Latest Amazon Linux version detected: {latest}")
    return latest


def get_latest_cves(stream="al2023", days=7):
    """
    Fetch Amazon Linux CVEs from ALAS RSS feed.
    Source: https://alas.aws.amazon.com/alas.rss
    """
    try:
        url = "https://alas.aws.amazon.com/alas.rss"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()

        xml_root = ET.fromstring(resp.content)
        items = xml_root.findall(".//item")
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

            cve_ids = [seg for seg in title.split() if seg.startswith("CVE-")]
            for cve_id in cve_ids:
                results.append({
                    "vendor": "amazonlinux",
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
                    "source": "amazonlinux",
                    "fetched_at": datetime.utcnow().isoformat() + "Z"
                })

        print(f"✅ Found {len(results)} Amazon Linux CVEs (last {days} days)")
        return results

    except Exception as e:
        print(f"❌ Failed to fetch Amazon Linux CVEs: {e}")
        return []


if __name__ == "__main__":
    print("\n--- Testing Amazon Linux Release Detection ---")
    get_latest_amazonlinux_version()
    print("\n--- Testing Amazon Linux CVE Fetch ---")
    cves = get_latest_cves()
    print(f"Sample CVEs: {cves[:2] if cves else 'No results'}")
