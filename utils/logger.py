# --- Logging Helpers ---

logged_skips = set()
logged_errors = set()

def log_skip(reason, detail):
    """Logs skipped URLs or actions, ensuring each unique skip is logged once."""
    key = ("skip", reason, detail)
    if key not in logged_skips:
        print(f"[x SKIPPED: {reason}] {detail}")
        logged_skips.add(key)

def log_error(source, url, err):
    """Logs errors with a source tag, ensuring each unique error is logged once."""
    key = ("error", source, url, str(err))
    if key not in logged_errors:
        print(f"[x ERROR:{source}] {url} – {err}")
        logged_errors.add(key)
