import time
import requests
from bs4 import BeautifulSoup
from googlesearch import search as google_search
from fake_useragent import UserAgent

# Global variable for search engine preference
preferred_engine = None
ua = UserAgent()

def get_headers(settings):
    """Returns headers based on user agent strategy from settings."""
    strategy = settings["request"].get("user_agent_strategy", "random").lower()
    if strategy == "random":
        user_agent = ua.random
    elif strategy == "fixed":
        user_agent = ua.chrome  # Fixed to a specific browser
    elif strategy == "rotate":
        # Rotate through a set of agents each call
        user_agent = ua.random  # Could be expanded for cycling logic
    else:
        print(f"[!] Unknown user_agent_strategy '{strategy}', defaulting to random.")
        user_agent = ua.random
    return {"User-Agent": user_agent}

def bing_search(query, settings):
    """Performs a Bing search and returns links."""
    print(f"[~] Using Bing Search for '{query}'")
    links = []
    delay = settings["request"]["delay_between_requests"]
    max_results = settings["fetch"]["engines"]["bing_max_results"]
    max_pages = settings["fetch"]["max_pages"]  # <-- pulled directly

    try:
        for page in range(max_pages):
            offset = page * settings["fetch"]["engines"]["bing_results_per_page"]
            resp = requests.get(
                settings["fetch"]["engines"]["bing_url"].format(query=query, offset=offset),
                headers=get_headers(settings),
                timeout=settings["request"]["timeout"]
            )
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.select("li.b_algo h2 a"):
                href = a.get('href')
                if href and href.startswith("http") and "bing.com" not in href:
                    links.append(href)
                if len(links) >= max_results:
                    break
            if len(links) >= max_results:
                break
            time.sleep(delay)
        print(f"[~] Bing returned {len(links)} results.")
    except Exception as e:
        print(f"[x ERROR:Bing] N/A – {e}")
    return links


def brave_search(query, settings):
    """Performs a Brave search and returns links."""
    print(f"[~] Using Brave Search for '{query}'")
    links = []
    delay = settings["request"]["delay_between_requests"]
    max_results = settings["fetch"]["engines"]["brave_max_results"]
    max_pages = settings["fetch"]["max_pages"]  # <-- pulled directly

    try:
        for page in range(max_pages):
            start = page * settings["fetch"]["engines"]["brave_results_per_page"]
            resp = requests.get(
                settings["fetch"]["engines"]["brave_url"].format(query=query, start=start),
                headers=get_headers(settings),
                timeout=settings["request"]["timeout"]
            )
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.select("a.result-header"):
                href = a.get('href')
                if href and href.startswith("http") and "search.brave.com" not in href:
                    links.append(href)
                if len(links) >= max_results:
                    break
            if len(links) >= max_results:
                break
            time.sleep(delay)
        print(f"[~] Brave returned {len(links)} results.")
    except Exception as e:
        print(f"[x ERROR:Brave] N/A – {e}")
    return links


def google_custom_search(query, settings):
    """Google search using googlesearch library, configurable from settings."""
    print(f"[~] Using Google Search for '{query}'")
    max_results = settings["fetch"]["engines"]["google_max_results"]
    try:
        return list(google_search(query, num_results=max_results))
    except Exception as e:
        print(f"[x ERROR:Google] N/A – {e}")
        return []

def get_search_engines(settings):
    """Returns list of search engines with their callables, fully from settings."""
    return [
        ("Google", lambda q: google_custom_search(q, settings)),
        ("Bing", lambda q: bing_search(q, settings)),
        ("Brave", lambda q: brave_search(q, settings))
    ]

def self_healing_search(query, settings):
    """Selects a working search engine and sticks to it for the whole run."""
    global preferred_engine
    engines = get_search_engines(settings)

    if preferred_engine:
        name, func = preferred_engine
        print(f"[~] Using preferred engine: {name}")
        try:
            links = func(query)
            if links:
                return links
            else:
                print(f"[x] Preferred engine {name} returned 0 links. Stopping.")
                exit(1)
        except Exception as e:
            print(f"[x ERROR:{name}] N/A – {e}")
            print(f"[x] Preferred engine {name} failed. Stopping.")
            exit(1)

    for name, func in engines:
        print(f"[~] Trying search with {name}...")
        try:
            links = func(query)
            if links:
                preferred_engine = (name, func)
                print(f"[✓] {name} selected as the preferred search engine.")
                return links
            else:
                print(f"[x] {name} returned 0 links. Trying next engine...")
        except Exception as e:
            print(f"[x ERROR:{name}] N/A – {e}")
            print(f"[x] {name} failed. Trying next engine...")

    print("[!] All search engines failed. Stopping crawler.")
    exit(1)
