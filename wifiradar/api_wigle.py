import sqlite3
import requests
import os
import time
import logging
import urllib.parse
from pathlib import Path

# Paths
LOG_DIR = Path.home() / "radar_logs"
CACHE_DB = LOG_DIR / "ssid_cache.sqlite"

# Logger
log = logging.getLogger("wigle_api")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

# Throttle mechanism
LAST_REQUEST_TIME = 0
RATE_LIMIT_DELAY = 1.5  # Seconds between requests to avoid bans

def _init_db():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS location_cache_v2 (
            ssid TEXT PRIMARY KEY,
            data TEXT,
            resolved_at INTEGER
        )
    ''')
    conn.commit()
    conn.close()

_init_db()

def get_wigle_token():
    # Try environment variable first
    token = os.environ.get("WIGLE_API_KEY")
    if token:
        return token
    # Try local file
    token_file = Path.cwd() / "wigle_api_key.txt"
    if token_file.exists():
        return token_file.read_text().strip()
    return None

import json

def check_cache(ssid):
    try:
        conn = sqlite3.connect(CACHE_DB)
        c = conn.cursor()
        c.execute("SELECT data FROM location_cache_v2 WHERE ssid=?", (ssid,))
        row = c.fetchone()
        conn.close()
        if row:
            if row[0] == "NEGATIVE": # Negative cache hit
                return None
            return json.loads(row[0])
    except Exception as e:
        log.error(f"Cache read error: {e}")
    return None

def write_cache(ssid, data_str):
    try:
        conn = sqlite3.connect(CACHE_DB)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO location_cache_v2 (ssid, data, resolved_at) VALUES (?, ?, ?)",
                  (ssid, data_str, int(time.time())))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Cache write error: {e}")

def resolve_ssid(ssid):
    """
    Attempts to resolve an SSID to coordinates.
    1. Checks local SQLite cache.
    2. If not found, checks for WiGLE token.
    3. Throttles and queries WiGLE API.
    4. Caches result.
    """
    if not ssid or len(ssid.strip()) == 0:
        return None
        
    cached = check_cache(ssid)
    if cached:
        return cached
        
    token = get_wigle_token()
    if not token:
        return None
        
    # Rate limiting
    global LAST_REQUEST_TIME
    now = time.time()
    if now - LAST_REQUEST_TIME < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - (now - LAST_REQUEST_TIME))
    LAST_REQUEST_TIME = time.time()
        
    headers = {
        "Authorization": f"Basic {token}",
        "Accept": "application/json"
    }
    
    encoded_ssid = urllib.parse.quote(ssid)
    url = f"https://api.wigle.net/api/v2/network/search?ssid={encoded_ssid}"
    
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") and data.get("results") and len(data["results"]) > 0:
                # Get up to 50 results
                results_list = []
                for res in data["results"][:50]:
                    lat = res.get("trilat")
                    lon = res.get("trilong")
                    if lat and lon:
                        results_list.append({"lat": lat, "lon": lon})
                        
                if results_list:
                    write_cache(ssid, json.dumps(results_list))
                    log.info(f"Resolved SSID '{ssid}' via WiGLE with {len(results_list)} locations")
                    return results_list
            else:
                # Negative cache: save as impossible coord to avoid re-querying dead SSIDs
                write_cache(ssid, "NEGATIVE")
                log.info(f"SSID '{ssid}' not found in WiGLE, caching as negative.")
        elif resp.status_code == 429:
            log.warning("WiGLE API Rate Limited! Slow down.")
            time.sleep(5)
        elif resp.status_code == 401:
            log.error("WiGLE API: Unauthorized. Invalid Basic Token.")
    except Exception as e:
        log.error(f"WiGLE API error for {ssid}: {e}")
        
    return None
