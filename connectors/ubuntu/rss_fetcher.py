import requests

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
    print(f"Latest Ubuntu version detected: {latest_version}")
    return latest_version


if __name__ == "__main__":
    get_latest_ubuntu_version()
