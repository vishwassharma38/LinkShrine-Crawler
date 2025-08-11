import os
import json
from bs4 import BeautifulSoup

# --- Load filters.json ---
script_dir = os.path.dirname(os.path.abspath(__file__))
filters_path = os.path.join(script_dir, "..", "config", "filters.json")

with open(filters_path, "r", encoding="utf-8") as f:
    filters = json.load(f)

AD_HOSTS = filters.get("ad_hosts", [])
AD_KEYWORDS = filters.get("ad_keywords", [])

def detect_ads(html):
    """
    Detects ads in the given HTML content using values from filters.json.

    Returns:
        int: Ad score based on detections.
    """
    soup = BeautifulSoup(html, "html.parser")
    ad_score = 0

    # Check <script> sources for ad hosts
    scripts = soup.find_all("script", src=True)
    for s in scripts:
        src_lower = s["src"].lower()
        if any(host in src_lower for host in AD_HOSTS):
            ad_score += 3

    # Check <iframe> sources for ad hosts or 'ad' keyword
    iframes = soup.find_all("iframe", src=True)
    for i in iframes:
        src_lower = i["src"].lower()
        if any(host in src_lower for host in AD_HOSTS):
            ad_score += 3
        elif "ad" in src_lower:
            ad_score += 1

    # Check HTML text for ad-related keywords
    html_lower = html.lower()
    for keyword in AD_KEYWORDS:
        if keyword in html_lower:
            ad_score += 1

    return ad_score
