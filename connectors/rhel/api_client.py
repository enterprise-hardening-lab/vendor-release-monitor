import requests
import re

def get_latest_rhel_version():
    """
    Fetch the latest RHEL version from the official Red Hat Security Data API.
    Endpoint: https://access.redhat.com/hydra/rest/securitydata/cve.json
    This API provides CVE metadata, including affected product versions.
    """
    URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    response = requests.get(URL, timeout=15)
    response.raise_for_status()

    data = response.json()
    versions = set()

    for entry in data:
        for pkg in entry.get("affected_release", []) or []:
            product_name = pkg.get("product_name", "")
            match = re.search(r"Red Hat Enterprise Linux (\d+(?:\.\d+)?)", product_name)
            if match:
                versions.add(match.group(1))

    if not versions:
        print("❌ Could not find RHEL versions in API response.")
        return None

    latest = sorted(versions, key=lambda v: [int(x) for x in v.split('.')], reverse=True)[0]
    print(f"Latest RHEL version detected: {latest}")
    return latest


if __name__ == "__main__":
    get_latest_rhel_version()
