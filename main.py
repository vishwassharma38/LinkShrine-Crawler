import glob
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from utils.ad_detection import detect_ads
from utils.logger import log_error, log_skip
from utils.save_results import save_results
from utils.search_engines import get_headers, self_healing_search


# --- Paths ---
script_dir = os.path.dirname(os.path.abspath(__file__))
filters_path = os.path.join(script_dir, "config", "filters.json")
settings_path = os.path.join(script_dir, "config", "settings.json")

# --- Load Configurations ---
with open(filters_path, "r", encoding="utf-8") as f:
    filters = json.load(f)

with open(settings_path, "r", encoding="utf-8") as f:
    settings = json.load(f)

# --- Filters ---
BLOCKED_DOMAINS = filters["blocked_domains"]
BLACKLIST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in filters["blacklist_patterns"]]
OFFICIAL_STREAMING_SITES = filters["official_streaming_sites"]
STREAM_HOSTS = filters["stream_hosts"]
AD_HOSTS = filters.get("ad_hosts", [])
AD_KEYWORDS = filters.get("ad_keywords", [])

# --- Settings ---
REQUEST_TIMEOUT = settings["request"]["timeout"]
DELAY_BETWEEN_REQUESTS = settings["request"]["delay_between_requests"]

NEEDED_UNOFFICIAL_SITES = settings["fetch"]["needed_unofficial_sites"]
MAX_PAGES = settings["fetch"]["max_pages"]
QUERIES = settings["fetch"]["queries"]

BING_URL = settings["fetch"]["engines"]["bing_url"]
BING_RESULTS_PER_PAGE = settings["fetch"]["engines"]["bing_results_per_page"]
BRAVE_URL = settings["fetch"]["engines"]["brave_url"]
BRAVE_RESULTS_PER_PAGE = settings["fetch"]["engines"]["brave_results_per_page"]

URL_LENGTH_SHORT = settings["url_rules"]["url_length_short"]
URL_LENGTH_MEDIUM = settings["url_rules"]["url_length_medium"]
MAX_PATH_SEGMENTS = settings["url_rules"]["max_path_segments"]
MAX_URL_LENGTH = settings["url_rules"]["max_url_length"]
BLOCKED_EXTENSIONS = settings["url_rules"]["blocked_extensions"]

HEAVY_ADS_THRESHOLD = settings["ads"]["heavy_ads_threshold"]
MODERATE_ADS_THRESHOLD = settings["ads"]["moderate_ads_threshold"]
LIGHT_ADS_THRESHOLD = settings["ads"]["light_ads_threshold"]

OUTPUT_FOLDER = os.path.join(script_dir, settings["output"]["folder"])
FILENAME_PATTERN = settings["output"]["filename_pattern"]
DATE_FORMAT = settings["output"]["date_format"]

# --- Site Checks ---
def is_probable_streaming_site(html_content):
    keywords = filters.get("stream_keywords", [])
    js_players = filters.get("stream_js_players", [])
    content = html_content.lower()
    keyword_hits = sum(1 for k in keywords if k in content)
    js_hits = sum(1 for p in js_players if p in content)
    return keyword_hits >= 5 or js_hits >= 2

def count_path_segments(path):
    return len([seg for seg in path.split("/") if seg.strip()])

def is_streaming_site(html, url):
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    url_length = len(url)

    if any(bad in domain for bad in BLOCKED_DOMAINS):
        log_skip("Blocked domain", domain)
        return False
    if any(p.search(url) for p in BLACKLIST_PATTERNS):
        log_skip("Blacklist pattern matched", url)
        return False
    if any(path.endswith(ext) for ext in BLOCKED_EXTENSIONS):
        log_skip("Unsupported file extension", path)
        return False
    if count_path_segments(path) > MAX_PATH_SEGMENTS:
        log_skip("Path too deep", f"{count_path_segments(path)} segments: {path}")
        return False
    if url_length > MAX_URL_LENGTH:
        log_skip("URL too long", f"{url_length} characters: {url}")
        return False

    soup = BeautifulSoup(html, "html.parser")
    has_video = bool(soup.find("video"))
    has_stream_host_iframe = any(
        any(host in iframe.get("src", "").lower() for host in STREAM_HOSTS)
        for iframe in soup.find_all("iframe")
    )
    has_keywords = is_probable_streaming_site(html)

    if url_length <= URL_LENGTH_SHORT:
        result = has_video or has_keywords or has_stream_host_iframe
    elif url_length <= URL_LENGTH_MEDIUM:
        result = (has_video and has_keywords) or has_stream_host_iframe
    else:
        result = has_video and has_keywords and has_stream_host_iframe

    if not result:
        log_skip("Failed content checks (video/iframe/keywords)", url)
    return result

def classify_site(url):
    domain = urlparse(url).netloc.lower()
    for official in OFFICIAL_STREAMING_SITES:
        if official.replace("www.", "") in domain:
            return "official"
    return "unofficial"

def get_site_name(html, url):
    ext = tldextract.extract(url)
    return ext.domain.lower()

def extract_description(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"name": "description"})
    if meta and meta.get("content"):
        return meta.get("content").strip()
    og = soup.find("meta", attrs={"property": "og:description"})
    if og and og.get("content"):
        return og.get("content").strip()
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    return title or "No description found"

def check_url(url, misc_urls, found_set):
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    url_length = len(url)
    path_segment_count = count_path_segments(path)

    # Skip blocked domains early
    if any(bad in domain for bad in BLOCKED_DOMAINS):
        log_skip("Blocked domain", url)
        return None

    # Skip official streaming sites early
    for official in OFFICIAL_STREAMING_SITES:
        if official.replace("www.", "") in domain:
            log_skip("Official site", url)
            return None

    try:
        response = requests.get(url, headers=get_headers(settings), timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            if is_streaming_site(response.text, url):
                # Always classify as unofficial (since official sites are skipped)
                site_name = get_site_name(response.text, url)
                ad_score = detect_ads(response.text)

                if ad_score >= HEAVY_ADS_THRESHOLD:
                    warning = "⚠️ This site contains heavy ads and pop-ups."
                elif ad_score >= MODERATE_ADS_THRESHOLD:
                    warning = "⚠️ This site has a moderate amount of ads."
                elif ad_score >= LIGHT_ADS_THRESHOLD:
                    warning = "ℹ️ Light ads present — browsing should be smooth."
                else:
                    warning = "✅ No ads detected — clean experience."

                print(f"[+ UNOFFICIAL] {url} — {site_name} | Ad Score: {ad_score}")

                return {
                    "url": url,
                    "url_name": site_name,
                    "status": "alive",
                    "last_checked": datetime.utcnow().isoformat() + "Z",
                    "type": "sub/dub",
                    "description": extract_description(response.text),
                    "ad_score": ad_score,
                    "warning": warning
                }, "unofficial"
        else:
            log_error("HTTP", url, f"Non-200 response: {response.status_code}")
    except Exception as e:
        log_error("Request", url, e)

    # Add to misc if short & simple
    if url_length <= URL_LENGTH_SHORT and path_segment_count <= MAX_PATH_SEGMENTS:
        if url not in found_set:
            found_set.add(url)
            misc_urls.append(url)
    return None

# --- Main Crawl ---
def format_duration(seconds):
    mins, secs = divmod(int(seconds), 60)
    hrs, mins = divmod(mins, 60)
    return f"{hrs:02}:{mins:02}:{secs:02}"

def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception as e:
        return None

def is_blocked_domain(url, blocked_domains):
    """Check if URL's domain is in the blocked domains list."""
    domain = extract_domain(url)
    if not domain:
        return False
    return domain in blocked_domains

def load_latest_results():
    """Loads the most recent results JSON from OUTPUT_FOLDER."""
    files = glob.glob(os.path.join(OUTPUT_FOLDER, "*.json"))
    if not files:
        return None
    latest_file = max(files, key=os.path.getmtime)
    with open(latest_file, "r", encoding="utf-8") as f:
        return json.load(f)

def preflight_check_existing(results):
    """
    Check all URLs in the JSON, update alive ones, remove dead ones and blocked domains.
    Blocked domains in 'misc' are removed but do NOT increase dead_count or trigger fetching replacements.
    """
    updated_unofficial = []
    updated_misc = []
    dead_count = 0
    blocked_count = 0

    # Get blocked domains from filters
    blocked_domains = filters.get("blocked_domains", [])
    blocked_domains = [domain.lower() for domain in blocked_domains]

    # Combine all URLs from unofficial_sites and misc for scanning
    all_entries = []
    for site in results.get("unofficial_sites", []):
        site_copy = site.copy()
        site_copy["_category"] = "unofficial"
        all_entries.append(site_copy)
    for url in results.get("misc", []):
        all_entries.append({"url": url, "_category": "misc"})

    total_sites = len(all_entries)
    print(f"[~] Preflight check: {total_sites} links found in the latest results file.")
    print(f"[~] Blocked domains loaded: {len(blocked_domains)}")
    print(f"[~] Scanning each link...")

    scanned_count = 0

    for entry in all_entries:
        scanned_count += 1
        url = entry.get("url")
        category = entry.get("_category")

        # Check if domain is blocked
        if is_blocked_domain(url, blocked_domains):
            blocked_count += 1
            domain = extract_domain(url)
            log_error("Blocked Domain", url, f"Domain '{domain}' is in blocked_domains list")

            if category == "unofficial":
                # Treat as dead for unofficial
                dead_count += 1
                print(f"[{scanned_count}/{total_sites}] Blocked (Unofficial): {url} | Dead: {dead_count}")
            else:
                # Misc blocked — remove but do NOT count as dead
                print(f"[{scanned_count}/{total_sites}] Blocked (Misc): {url} | Dead unchanged: {dead_count}")
            continue

        # If not blocked, perform HTTP check only for unofficial sites
        if category == "unofficial":
            try:
                response = requests.get(url, headers=get_headers(settings), timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    ad_score = detect_ads(response.text)
                    entry["last_checked"] = datetime.utcnow().isoformat() + "Z"
                    entry["ad_score"] = ad_score

                    if ad_score >= HEAVY_ADS_THRESHOLD:
                        entry["warning"] = "⚠️ This site contains heavy ads and pop-ups."
                    elif ad_score >= MODERATE_ADS_THRESHOLD:
                        entry["warning"] = "⚠️ This site has a moderate amount of ads."
                    elif ad_score >= LIGHT_ADS_THRESHOLD:
                        entry["warning"] = "ℹ️ Light ads present — browsing should be smooth."
                    else:
                        entry["warning"] = "✅ No ads detected — clean experience."

                    updated_unofficial.append(entry)
                else:
                    dead_count += 1
                    log_error("HTTP", url, f"Non-200 response: {response.status_code}")
            except Exception as e:
                dead_count += 1
                log_error("Request", url, e)
        else:
            # Keep misc URLs that are not blocked
            updated_misc.append(url)

        # Progress output
        print(f"[{scanned_count}/{total_sites}] Checked: {url} | "
              f"Alive Unofficial: {len(updated_unofficial)} | Dead: {dead_count} | Misc: {len(updated_misc)}")

    updated_unofficial.sort(key=lambda x: x.get("ad_score", 0))

    if blocked_count > 0:
        print(f"\n[!] Blocked domains removed: {blocked_count} (Misc-blocked not counted as dead)")

    return updated_unofficial, updated_misc, dead_count

def crawl_anime_sites():
    print("\n[~] Starting pre-flight check for existing results...\n")
    existing_data = load_latest_results()
    results = {"unofficial_sites": [], "misc": []}

    needed_unofficial_sites = NEEDED_UNOFFICIAL_SITES  # use global constant!

    if existing_data:
        updated_sites, updated_misc, dead_count = preflight_check_existing(existing_data)
        results["unofficial_sites"] = updated_sites
        results["misc"] = updated_misc

        alive = len(updated_sites)
        dead = dead_count
        needed = needed_unofficial_sites

        # --- New Logic ---
        if alive >= needed:
            # Already enough, just replace dead
            dead_links_to_fetch = dead
        else:
            shortage = needed - alive
            if alive + dead == needed:
                dead_links_to_fetch = dead
            else:
                dead_links_to_fetch = shortage + dead

        print("\n[✓] Preflight Summary:")
        print(f"    Alive Links: {alive}")
        print(f"    Dead Links (Unofficial only): {dead}")
        print(f"    Misc Links: {len(updated_misc)}")
        print(f"    Needed Unofficial Sites: {needed}")
        print(f"    Will fetch: {dead_links_to_fetch} new unofficial sites")

    else:
        results["misc"] = []
        print("[!] No existing results found — starting from scratch.")
        dead_links_to_fetch = needed_unofficial_sites

    if dead_links_to_fetch <= 0:
        print("\n[✓] No new unofficial links required. Updating file and finishing.")
        save_results(results, OUTPUT_FOLDER, FILENAME_PATTERN, DATE_FORMAT)
        return

    print(f"\n[~] Crawling to fetch {dead_links_to_fetch} new unofficial sites...\n")
    total_checked = 0
    found_set = {site["url"] for site in results["unofficial_sites"]}
    misc_urls = []
    query_index = 0
    round_count = 1
    start_time = time.time()

    initial_unofficial_count = len(results["unofficial_sites"])

    while len(results["unofficial_sites"]) < (initial_unofficial_count + dead_links_to_fetch):
        if query_index >= len(QUERIES):
            query_index = 0
            round_count += 1
            print(f"\n[~] Starting round {round_count} of queries...\n")

        query = QUERIES[query_index]
        query_index += 1

        urls = self_healing_search(query, settings)

        for url in urls:
            if url in found_set:
                continue

            site_info = check_url(url, misc_urls, found_set)
            total_checked += 1

            if site_info:
                site, category = site_info
                if category == "unofficial":
                    found_set.add(site["url"])
                    results["unofficial_sites"].append(site)

            elapsed = format_duration(time.time() - start_time)
            print(f"[~] Progress: {total_checked} URLs checked | "
                  f"{len(results['unofficial_sites'])} unofficial | "
                  f"{len(misc_urls)} misc | Time Elapsed: {elapsed}")

            if len(results["unofficial_sites"]) >= (initial_unofficial_count + dead_links_to_fetch):
                break

            time.sleep(DELAY_BETWEEN_REQUESTS)

    results["unofficial_sites"].sort(key=lambda x: x.get("ad_score", 0))
    results["misc"].extend(misc_urls)
    results["misc"] = list(set(results["misc"]))

    save_results(results, OUTPUT_FOLDER, FILENAME_PATTERN, DATE_FORMAT)
    final_time = format_duration(time.time() - start_time)
    print(f"\n[✓] Finished! Checked {total_checked} URLs in {final_time}.")
    print(f"[✓] Found {len(results['unofficial_sites'])} unofficial sites in total.")

if __name__ == "__main__":
    crawl_anime_sites()