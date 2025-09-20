import time
import requests
from bs4 import BeautifulSoup
from googlesearch import search as google_search
from fake_useragent import UserAgent
import concurrent.futures
import threading
from typing import List, Tuple, Callable, Optional

# Global variable for search engine preference
preferred_engine = None
ua = UserAgent()
# Thread lock for thread-safe operations
engine_lock = threading.Lock()

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
    max_pages = settings["fetch"]["max_pages"]

    try:
        for page in range(max_pages):
            offset = page * settings["fetch"]["engines"]["bing_results_per_page"]
            url = settings["fetch"]["engines"]["bing_url"].format(query=query, offset=offset)
            
            resp = requests.get(url, headers=get_headers(settings), timeout=settings["request"]["timeout"])
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Try multiple selectors for Bing's changing structure
            selectors = [
                "li.b_algo h2 a",           # Original selector
                "h2 a[href^='http']",       # More general h2 links
                ".b_algo a[href^='http']",  # Any link in algo results
                "li.b_algo a",              # Broader algo links
                ".b_title a",               # Title links
                "h3 a[href^='http']",       # H3 title links
                "a[href^='http']"           # Fallback: any external link
            ]
            
            page_links = []
            
            for selector in selectors:
                elements = soup.select(selector)
                for a in elements:
                    href = a.get('href')
                    if (href and 
                        href.startswith("http") and 
                        "bing.com" not in href and 
                        "microsoft.com" not in href and
                        href not in page_links):  # Avoid duplicates
                        page_links.append(href)
                if page_links:
                    break
            
            links.extend(page_links)
            
            if len(links) >= max_results:
                break
                
            time.sleep(delay)
            
        print(f"[✓] Bing returned {len(links)} results.")
        return links[:max_results]
    except Exception as e:
        print(f"[x ERROR:Bing] {e}")
        return []

def brave_search(query, settings):
    """Performs a Brave search and returns links."""
    print(f"[~] Using Brave Search for '{query}'")
    links = []
    delay = settings["request"]["delay_between_requests"]
    max_results = settings["fetch"]["engines"]["brave_max_results"]
    max_pages = settings["fetch"]["max_pages"]

    try:
        for page in range(max_pages):
            start = page * settings["fetch"]["engines"]["brave_results_per_page"]
            url = settings["fetch"]["engines"]["brave_url"].format(query=query, start=start)
            
            resp = requests.get(url, headers=get_headers(settings), timeout=settings["request"]["timeout"])
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Try multiple selectors
            selectors = ["a.result-header", "a[href^='http']", ".result a", "div[data-type='web'] a"]
            page_links = []
            
            for selector in selectors:
                elements = soup.select(selector)
                for a in elements:
                    href = a.get('href')
                    if href and href.startswith("http") and "search.brave.com" not in href:
                        page_links.append(href)
                if page_links:
                    break
            
            links.extend(page_links)
            
            if len(links) >= max_results:
                break
                
            time.sleep(delay)
            
        print(f"[✓] Brave returned {len(links)} results.")
        return links[:max_results]
    except Exception as e:
        print(f"[x ERROR:Brave] {e}")
        return []

def duckduckgo_search(query, settings):
    """Performs a DuckDuckGo search and returns links."""
    print(f"[~] Using DuckDuckGo Search for '{query}'")
    links = []
    delay = settings["request"]["delay_between_requests"]
    max_results = settings["fetch"]["engines"]["duckduckgo_max_results"]
    max_pages = settings["fetch"]["max_pages"]

    try:
        for page in range(max_pages):
            # DuckDuckGo uses 's' parameter for pagination (s=0, s=30, s=60, etc.)
            start = page * settings["fetch"]["engines"]["duckduckgo_results_per_page"]
            url = settings["fetch"]["engines"]["duckduckgo_url"].format(query=query, start=start)
            
            # DuckDuckGo is sensitive to headers, use a more complete header set
            headers = get_headers(settings)
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            resp = requests.get(url, headers=headers, timeout=settings["request"]["timeout"])
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Try multiple selectors for DuckDuckGo's structure
            selectors = [
                "a[data-testid='result-title-a']",  # Main result links (newer structure)
                ".result__a",                       # Classic result links
                "h2 a[href^='http']",              # H2 title links
                ".result a[href^='http']",         # Any result link
                "a[href^='http']:not([href*='duckduckgo.com'])",  # External links excluding DDG
                ".web-result a",                   # Web result links
                "[data-result] a"                  # Data result links
            ]
            
            page_links = []
            
            for selector in selectors:
                elements = soup.select(selector)
                for a in elements:
                    href = a.get('href')
                    if (href and 
                        href.startswith("http") and 
                        "duckduckgo.com" not in href and
                        "duck.co" not in href and  # DDG short URLs
                        href not in page_links):  # Avoid duplicates
                        page_links.append(href)
                if page_links:
                    break
            
            # If no direct links found, try to extract from redirect URLs
            if not page_links:
                redirect_elements = soup.find_all('a', href=True)
                for a in redirect_elements:
                    href = a.get('href')
                    if href and '/l/?uddg=' in href:
                        # Extract the actual URL from DuckDuckGo redirect
                        try:
                            import urllib.parse
                            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                            if 'uddg' in parsed:
                                actual_url = urllib.parse.unquote(parsed['uddg'][0])
                                if actual_url.startswith('http') and actual_url not in page_links:
                                    page_links.append(actual_url)
                        except:
                            continue
            
            links.extend(page_links)
            
            if len(links) >= max_results:
                break
                
            time.sleep(delay)

        print(f"[✓] DuckDuckGo returned {len(links)} results.")
        return links[:max_results]
    except Exception as e:
        print(f"[x ERROR:DuckDuckGo] {e}")
        return []

def google_custom_search(query, settings):
    """Google search using googlesearch library, configurable from settings."""
    print(f"[~] Using Google Search for '{query}'")
    max_results = settings["fetch"]["engines"]["google_max_results"]
    try:
        results = list(google_search(query, num_results=max_results))
        print(f"[✓] Google returned {len(results)} results.")
        return results
    except Exception as e:
        print(f"[x ERROR:Google] {e}")
        return []

def execute_search_engine(engine_name: str, search_func: Callable, query: str) -> Tuple[str, List[str]]:
    """Execute a single search engine and return results with engine name."""
    try:
        results = search_func(query)
        return engine_name, results if results else []
    except Exception as e:
        print(f"[x ERROR:{engine_name}] {e}")
        return engine_name, []

def get_search_engines(settings):
    """Returns list of search engines with their callables, fully from settings."""
    return [
        ("Google", lambda q: google_custom_search(q, settings)),
        ("Bing", lambda q: bing_search(q, settings)),
        ("Brave", lambda q: brave_search(q, settings)),
        ("DuckDuckGo", lambda q: duckduckgo_search(q, settings))
    ]

def parallel_search(query, settings, max_workers: int = 4) -> List[str]:
    """
    Execute all search engines in parallel and combine results.
    Returns combined results from all successful engines.
    Updated to handle 4 engines instead of 3.
    """
    engines = get_search_engines(settings)
    all_links = []
    successful_engines = []
    failed_engines = []
    
    print(f"[~] Starting parallel search for '{query}' with {len(engines)} engines...")
    
    # Use ThreadPoolExecutor for parallel execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all search tasks
        future_to_engine = {
            executor.submit(execute_search_engine, name, func, query): name 
            for name, func in engines
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_engine):
            engine_name = future_to_engine[future]
            try:
                name, links = future.result()
                if links:
                    print(f"[✓] {name} completed successfully with {len(links)} results")
                    all_links.extend(links)
                    successful_engines.append(name)
                else:
                    print(f"[!] {name} completed but returned 0 results")
                    failed_engines.append(name)
            except Exception as e:
                print(f"[x ERROR:{engine_name}] Exception during execution: {e}")
                failed_engines.append(engine_name)
    
    # Remove duplicates while preserving order
    unique_links = []
    seen_links = set()
    for link in all_links:
        if link not in seen_links:
            unique_links.append(link)
            seen_links.add(link)
    
    print(f"[~] Parallel search completed:")
    print(f"    Successful engines: {successful_engines}")
    print(f"    Failed engines: {failed_engines}")
    print(f"    Total unique links: {len(unique_links)}")
    
    return unique_links

def self_healing_search(query, settings):
    """
    Performs parallel search across all engines, with fallback behavior.
    Only fails if all engines fail to return results.
    """
    global preferred_engine
    
    # If we have a preferred engine, try it first
    if preferred_engine:
        name, func = preferred_engine
        print(f"[~] Trying preferred engine: {name}")
        try:
            links = func(query)
            if links:
                print(f"[✓] Preferred engine {name} succeeded with {len(links)} results")
                return links
            else:
                print(f"[!] Preferred engine {name} returned 0 results, falling back to parallel search")
        except Exception as e:
            print(f"[x ERROR:{name}] Preferred engine failed: {e}")
            print(f"[!] Falling back to parallel search")
    
    # Perform parallel search
    all_results = parallel_search(query, settings)
    
    if all_results:
        # Set the first successful engine as preferred for future searches
        # This is a simplified approach - you could implement more sophisticated logic
        with engine_lock:
            if not preferred_engine:
                engines = get_search_engines(settings)
                # Try to determine which engine worked best (simplified)
                for name, func in engines:
                    try:
                        test_results = func(query)
                        if test_results:
                            preferred_engine = (name, func)
                            print(f"[✓] {name} set as preferred engine for future searches")
                            break
                    except:
                        continue
        
        return all_results
    else:
        print("[!] All search engines failed or returned 0 results. Stopping crawler.")
        exit(1)

def priority_parallel_search(query, settings, priority_order: Optional[List[str]] = None) -> List[str]:
    """
    Advanced parallel search that respects priority order but still runs all engines.
    
    Args:
        query: Search query
        settings: Configuration settings
        priority_order: Optional list of engine names in priority order ['Google', 'Bing', 'Brave', 'DuckDuckGo']
    
    Returns:
        Combined results with priority engine results first
    """
    if priority_order is None:
        priority_order = ['Google', 'Bing', 'Brave', 'DuckDuckGo']
    
    engines = get_search_engines(settings)
    engine_dict = {name: func for name, func in engines}
    
    # Reorder engines based on priority
    ordered_engines = []
    for priority_name in priority_order:
        if priority_name in engine_dict:
            ordered_engines.append((priority_name, engine_dict[priority_name]))
    
    # Add any remaining engines not in priority list
    for name, func in engines:
        if name not in priority_order:
            ordered_engines.append((name, func))
    
    print(f"[~] Starting priority parallel search for '{query}'")
    print(f"    Priority order: {[name for name, _ in ordered_engines]}")
    
    all_results = []
    successful_engines = []
    
    # Execute all engines in parallel but organize results by priority
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ordered_engines)) as executor:
        future_to_engine = {
            executor.submit(execute_search_engine, name, func, query): (name, idx) 
            for idx, (name, func) in enumerate(ordered_engines)
        }
        
        # Store results with their priority index
        results_with_priority = []
        
        for future in concurrent.futures.as_completed(future_to_engine):
            engine_name, priority_idx = future_to_engine[future]
            try:
                name, links = future.result()
                if links:
                    results_with_priority.append((priority_idx, name, links))
                    successful_engines.append(name)
                    print(f"[✓] {name} completed with {len(links)} results")
                else:
                    print(f"[!] {name} returned 0 results")
            except Exception as e:
                print(f"[x ERROR:{engine_name}] {e}")
    
    # Sort by priority and combine results
    results_with_priority.sort(key=lambda x: x[0])  # Sort by priority index
    
    for _, name, links in results_with_priority:
        all_results.extend(links)
    
    # Remove duplicates while preserving priority order
    unique_results = []
    seen_links = set()
    for link in all_results:
        if link not in seen_links:
            unique_results.append(link)
            seen_links.add(link)
    
    print(f"[~] Priority parallel search completed:")
    print(f"    Successful engines (in priority order): {successful_engines}")
    print(f"    Total unique results: {len(unique_results)}")
    
    return unique_results