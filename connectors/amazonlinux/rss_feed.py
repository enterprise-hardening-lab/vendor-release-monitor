import requests
from xml.etree import ElementTree

def get_latest_amazonlinux_version():
    """
    Fetch the latest Amazon Linux 2/2023 release from the official RSS feed.
    """
    FEED_URL = "https://cdn.amazonlinux.com/2/relnotes/rss.xml"
    try:
        response = requests.get(FEED_URL, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"❌ Failed to fetch Amazon Linux RSS feed: {e}")
        return None

    try:
        root = ElementTree.fromstring(response.text)
    except ElementTree.ParseError as e:
        print(f"❌ Failed to parse RSS feed: {e}")
        return None

    # Extract first <item><title>
    latest_item = root.find("./channel/item/title")
    if latest_item is None:
        print("⚠️ No release entries found in RSS feed.")
        return None

    title = latest_item.text.strip()
    print(f"Latest Amazon Linux version detected: {title}")
    return title


if __name__ == "__main__":
    get_latest_amazonlinux_version()
