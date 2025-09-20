import asyncio
import glob
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import aiohttp
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
BLACKLIST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in filters["blacklist_patterns"]] if filters["blacklist_patterns"] else []
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
    
    # Skip processing if both arrays are empty
    if not keywords and not js_players:
        return False
    
    content = html_content.lower()
    keyword_hits = sum(1 for k in keywords if k in content) if keywords else 0
    js_hits = sum(1 for p in js_players if p in content) if js_players else 0
    return keyword_hits >= 5 or js_hits >= 2

def count_path_segments(path):
    return len([seg for seg in path.split("/") if seg.strip()])

def matches_site_description(html, mode="unofficial"):
    """Check if <title>, og:title, meta description, or og:description 
    contains any keywords from filters['site_description'].

    Thresholds:
    - unofficial: at least 2 keyword hits
    - misc: at least 1 keyword hit
    """
    site_desc_keywords = filters.get("site_description", [])
    if not site_desc_keywords:
        return False

    soup = BeautifulSoup(html, "html.parser")
    desc_content = ""

    # <title>
    title_tag = soup.find("title")
    if title_tag and title_tag.text:
        desc_content += title_tag.text.lower() + " "

    # og:title
    og_title = soup.find("meta", attrs={"property": "og:title"})
    if og_title and og_title.get("content"):
        desc_content += og_title.get("content").lower() + " "

    # meta description
    meta = soup.find("meta", attrs={"name": "description"})
    if meta and meta.get("content"):
        desc_content += meta.get("content").lower() + " "

    # og:description
    og_desc = soup.find("meta", attrs={"property": "og:description"})
    if og_desc and og_desc.get("content"):
        desc_content += og_desc.get("content").lower()

    if not desc_content.strip():
        return False

    # Count keyword hits
    hits = sum(1 for keyword in site_desc_keywords if keyword in desc_content)

    if mode == "misc":
        return hits >= 1 # for "misc"
    return hits >= 2  # for "unofficial"

def is_streaming_site(html, url):
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    url_length = len(url)

    # Skip blocked domains check if list is empty
    if BLOCKED_DOMAINS and any(bad in domain for bad in BLOCKED_DOMAINS):
        log_skip("Blocked domain", domain)
        return False
    
    # Skip blacklist pattern check if list is empty
    if BLACKLIST_PATTERNS and any(p.search(url) for p in BLACKLIST_PATTERNS):
        log_skip("Blacklist pattern matched", url)
        return False
    
    # Skip blocked extensions check if list is empty
    if BLOCKED_EXTENSIONS and any(path.endswith(ext) for ext in BLOCKED_EXTENSIONS):
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
    
    # Skip stream host iframe check if list is empty
    has_stream_host_iframe = False
    if STREAM_HOSTS:
        has_stream_host_iframe = any(
            any(host in iframe.get("src", "").lower() for host in STREAM_HOSTS)
            for iframe in soup.find_all("iframe")
        )
    
    has_keywords = is_probable_streaming_site(html)

    if url_length <= URL_LENGTH_SHORT:
        result = (has_video or has_keywords or has_stream_host_iframe) and matches_site_description(html, "unofficial")
    elif url_length <= URL_LENGTH_MEDIUM:
        result = (has_video and has_keywords) or has_stream_host_iframe
    else:
        result = has_video and has_keywords and has_stream_host_iframe

    if not result:
        log_skip("Failed content checks (video/iframe/keywords)", url)
    return result

def classify_site(url):
    domain = urlparse(url).netloc.lower()
    # Skip official streaming sites check if list is empty
    if OFFICIAL_STREAMING_SITES:
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

async def check_url(session, url, misc_urls, found_set):
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    url_length = len(url)
    path_segment_count = count_path_segments(path)
    parsed_url = urlparse(url)

    # Skip blocked domains early (only if list is not empty)
    if BLOCKED_DOMAINS and any(bad in domain for bad in BLOCKED_DOMAINS):
        log_skip("Blocked domain", url)
        return None

    # Skip official streaming sites early (only if list is not empty)
    if OFFICIAL_STREAMING_SITES:
        for official in OFFICIAL_STREAMING_SITES:
            if official.replace("www.", "") in domain:
                log_skip("Official site", url)
                return None

    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        async with session.get(url, headers=get_headers(settings), timeout=timeout) as response:
            if response.status == 200:
                html_content = await response.text()
                if is_streaming_site(html_content, url):
                    # Always classify as unofficial (since official sites are skipped)
                    site_name = get_site_name(html_content, url)
                    ad_score = detect_ads(html_content)

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
                        "description": extract_description(html_content),
                        "ad_score": ad_score,
                        "warning": warning
                    }, "unofficial"

                # Add to misc if short/simple, no query params, AND passes description check
                if (url_length <= URL_LENGTH_SHORT and 
                    path_segment_count <= MAX_PATH_SEGMENTS and 
                    not parsed_url.query and 
                    matches_site_description(html_content, "misc")):
                    if url not in found_set:
                        found_set.add(url)
                        misc_urls.append(url)
                        print(f"[+ MISC] {url}")
            else:
                log_error("HTTP", url, f"Non-200 response: {response.status}")
    except Exception as e:
        log_error("Request", url, e)

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
    # Skip check if blocked_domains is empty
    if not blocked_domains:
        return False
    
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

async def check_single_url_preflight(session, entry, blocked_domains):
    """Check a single URL during preflight check."""
    url = entry.get("url")
    category = entry.get("_category")

    # Check if domain is blocked (skip if blocked_domains is empty)
    if blocked_domains and is_blocked_domain(url, blocked_domains):
        domain = extract_domain(url)
        log_error("Blocked Domain", url, f"Domain '{domain}' is in blocked_domains list")
        return None, "blocked", category

    # If not blocked, perform HTTP check only for unofficial sites
    if category == "unofficial":
        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            async with session.get(url, headers=get_headers(settings), timeout=timeout) as response:
                if response.status == 200:
                    html_content = await response.text()
                    ad_score = detect_ads(html_content)
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

                    return entry, "alive", category

                elif response.status == 403:
                    # Special handling: keep site in list, don't mark dead
                    entry["last_checked"] = datetime.utcnow().isoformat() + "Z"
                    entry["warning"] = "⚠️ Site responded with 403 (Forbidden). Preserved in list."
                    return entry, "forbidden", category

                else:
                    # Other non-200 responses → dead
                    log_error("HTTP", url, f"Non-200 response: {response.status}")
                    return None, "dead", category

        except Exception as e:
            log_error("Request", url, e)
            return None, "dead", category
    else:
        # Keep misc URLs that are not blocked
        return url, "alive", category

async def preflight_check_existing(results):
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
    blocked_domains = [domain.lower() for domain in blocked_domains] if blocked_domains else []

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

    # Create aiohttp session with connector settings
    connector = aiohttp.TCPConnector(limit=settings["request"]["max_concurrent_requests"])
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(settings["request"]["max_concurrent_requests"])
        
        async def check_with_semaphore(entry):
            async with semaphore:
                return await check_single_url_preflight(session, entry, blocked_domains)
        
        # Process all URLs concurrently
        tasks = [check_with_semaphore(entry) for entry in all_entries]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

    scanned_count = 0
    for i, result in enumerate(results_list):
        scanned_count += 1
        entry = all_entries[i]
        url = entry.get("url")
        
        if isinstance(result, Exception):
            # Handle exceptions
            log_error("Async Request", url, result)
            if entry.get("_category") == "unofficial":
                dead_count += 1
            continue
            
        entry_result, status, category = result

        if status == "blocked":
            blocked_count += 1
            if category == "unofficial":
                # Treat as dead for unofficial
                dead_count += 1
                print(f"[{scanned_count}/{total_sites}] Blocked (Unofficial): {url} | Dead: {dead_count}")
            else:
                # Misc blocked — remove but do NOT count as dead
                print(f"[{scanned_count}/{total_sites}] Blocked (Misc): {url} | Dead unchanged: {dead_count}")
        elif status in ["alive", "forbidden"]:
            if category == "unofficial":
                updated_unofficial.append(entry_result)
            else:
                updated_misc.append(entry_result)
            if status == "forbidden":
                print(f"[{scanned_count}/{total_sites}] 403 but preserved: {url}")
        elif status == "dead":
            if category == "unofficial":
                dead_count += 1

        # Progress output
        print(f"[{scanned_count}/{total_sites}] Checked: {url} | "
              f"Alive Unofficial: {len(updated_unofficial)} | Dead: {dead_count} | Misc: {len(updated_misc)}")

    updated_unofficial.sort(key=lambda x: x.get("ad_score", 0))

    if blocked_count > 0:
        print(f"\n[!] Blocked domains removed: {blocked_count} (Misc-blocked not counted as dead)")

    return updated_unofficial, updated_misc, dead_count

async def check_url_batch(session, urls, misc_urls, found_set, semaphore):
    """Process a batch of URLs concurrently."""
    async def check_single_with_semaphore(url):
        async with semaphore:
            return await check_url_async(session, url, misc_urls, found_set)
    
    tasks = [check_single_with_semaphore(url) for url in urls if url not in found_set]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = []
    for result in results:
        if isinstance(result, Exception):
            continue
        if result is not None:
            valid_results.append(result)
    
    return valid_results

async def check_url_async(session, url, misc_urls, found_set):
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    url_length = len(url)
    path_segment_count = count_path_segments(path)
    parsed_url = urlparse(url)

    # Skip blocked domains early (only if list is not empty)
    if BLOCKED_DOMAINS and any(bad in domain for bad in BLOCKED_DOMAINS):
        log_skip("Blocked domain", url)
        return None

    # Skip official streaming sites early (only if list is not empty)
    if OFFICIAL_STREAMING_SITES:
        for official in OFFICIAL_STREAMING_SITES:
            if official.replace("www.", "") in domain:
                log_skip("Official site", url)
                return None

    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        async with session.get(url, headers=get_headers(settings), timeout=timeout) as response:
            if response.status == 200:
                html_content = await response.text()
                if is_streaming_site(html_content, url):
                    # Always classify as unofficial
                    site_name = get_site_name(html_content, url)
                    ad_score = detect_ads(html_content)

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
                        "description": extract_description(html_content),
                        "ad_score": ad_score,
                        "warning": warning
                    }, "unofficial"

                # Add to misc if short/simple, no query params, AND passes description check
                if (url_length <= URL_LENGTH_SHORT and 
                    path_segment_count <= MAX_PATH_SEGMENTS and 
                    not parsed_url.query and 
                    matches_site_description(html_content, "misc")):
                    if url not in found_set:
                        found_set.add(url)
                        misc_urls.append(url)
                        print(f"[+ MISC] {url}")
            else:
                log_error("HTTP", url, f"Non-200 response: {response.status}")
    except Exception as e:
        log_error("Request", url, e)

    return None

async def crawl_anime_sites():
    print("\n[~] Starting pre-flight check for existing results...\n")
    existing_data = load_latest_results()
    results = {"unofficial_sites": [], "misc": []}

    needed_unofficial_sites = NEEDED_UNOFFICIAL_SITES  # use global constant!

    if existing_data:
        updated_sites, updated_misc, dead_count = await preflight_check_existing(existing_data)
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

    # --- Patched Preflight Backup ---
    if dead_links_to_fetch <= 0:
        print("\n[✓] No new unofficial links required. Updating file and finishing.")

        # Use existing data if available to keep metadata intact
        if existing_data:
            results = existing_data

        # Refresh last_checked so backup always reflects the check
        for site in results.get("unofficial_sites", []):
            site["last_checked"] = datetime.utcnow().isoformat() + "Z"

        # Save (this also pushes to Supabase)
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

    # Create aiohttp session with connector settings
    connector = aiohttp.TCPConnector(limit=settings["request"]["max_concurrent_requests"])
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    semaphore = asyncio.Semaphore(settings["request"]["max_concurrent_requests"])

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        while len(results["unofficial_sites"]) < (initial_unofficial_count + dead_links_to_fetch):
            if query_index >= len(QUERIES):
                query_index = 0
                round_count += 1
                print(f"\n[~] Starting round {round_count} of queries...\n")

            query = QUERIES[query_index]
            query_index += 1

            # Get URLs from search (this remains synchronous as it's external dependency)
            urls = self_healing_search(query, settings)
            
            # Filter out already found URLs
            new_urls = [url for url in urls if url not in found_set]
            
            if not new_urls:
                continue

            # Process URLs in batches
            batch_results = await check_url_batch(session, new_urls, misc_urls, found_set, semaphore)
            
            for site_info in batch_results:
                if site_info:
                    site, category = site_info
                    if category == "unofficial":
                        found_set.add(site["url"])
                        results["unofficial_sites"].append(site)

            total_checked += len(new_urls)
            elapsed = format_duration(time.time() - start_time)
            print(f"[~] Progress: {total_checked} URLs checked | "
                  f"{len(results['unofficial_sites'])} unofficial | "
                  f"{len(misc_urls)} misc | Time Elapsed: {elapsed}")

            if len(results["unofficial_sites"]) >= (initial_unofficial_count + dead_links_to_fetch):
                break

            # Add delay between query batches instead of individual requests
            await asyncio.sleep(DELAY_BETWEEN_REQUESTS)

    results["unofficial_sites"].sort(key=lambda x: x.get("ad_score", 0))
    results["misc"].extend(misc_urls)
    results["misc"] = list(set(results["misc"]))

    save_results(results, OUTPUT_FOLDER, FILENAME_PATTERN, DATE_FORMAT)
    final_time = format_duration(time.time() - start_time)
    print(f"\n[✓] Finished! Checked {total_checked} URLs in {final_time}.")
    print(f"[✓] Found {len(results['unofficial_sites'])} unofficial sites in total.")


if __name__ == "__main__":
    asyncio.run(crawl_anime_sites())