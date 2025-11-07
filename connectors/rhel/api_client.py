import requests
import re
import sys

def get_latest_rhel_version():
    """
    Fetch the latest RHEL version from the official Red Hat Security Data API.
    Endpoint: https://access.redhat.com/hydra/rest/securitydata/cve.json
    Parses CVE metadata to extract affected RHEL product versions.
    """

    URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"

    try:
        response = requests.get(URL, timeout=20)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"❌ Failed to query Red Hat API: {e}")
        sys.exit(1)

    try:
        data = response.json()
    except Exception as e:
        print(f"❌ Failed to parse JSON response: {e}")
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
        sys.exit(0)

    latest = sorted(versions, key=lambda v: [int(x) for x in v.split('.')], reverse=True)[0]
    print(f"Latest RHEL version detected: {latest}")
    return latest


if __name__ == "__main__":
    get_latest_rhel_version()
