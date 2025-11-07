import requests
from bs4 import BeautifulSoup

def get_latest_ubuntu_version():
    """
    Fetch the latest Ubuntu release version from the official releases RSS feed.
    """
    RSS_FEED = "https://releases.ubuntu.com/rss.xml"
    response = requests.get(RSS_FEED, timeout=10)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "xml")
    latest_item = soup.find("item")

    if not latest_item:
        print("❌ Could not parse Ubuntu RSS feed.")
        return None

    title = latest_item.title.text.strip()
    print(f"Latest Ubuntu version detected: {title}")
    return title


if __name__ == "__main__":
    get_latest_ubuntu_version()
