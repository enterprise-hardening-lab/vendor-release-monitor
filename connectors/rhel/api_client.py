import requests
import re

def get_latest_rhel_version():
    """
    Fetch the latest RHEL release version from the official Red Hat product metadata API.
    This endpoint does not require authentication for general release information.
    """
    URL = "https://access.redhat.com/labs/securitydataapi/ovals"
    response = requests.get(URL, timeout=10)
    response.raise_for_status()

    # Example API returns a list of OVAL definitions; extract RHEL versions.
    data = response.json()
    versions = set()

    for item in data:
        product = item.get("product_name", "")
        match = re.search(r"Red Hat Enterprise Linux (\d+(\.\d+)?)", product)
        if match:
            versions.add(match.group(1))

    if not versions:
        print("❌ Could not find RHEL versions in API response.")
        return None

    latest = sorted(list(versions), key=lambda v: [int(x) for x in v.split('.')], reverse=True)[0]
    print(f"Latest RHEL version detected: {latest}")
    return latest


if __name__ == "__main__":
    get_latest_rhel_version()
