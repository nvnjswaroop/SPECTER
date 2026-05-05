"""
SPECTER HTTP Client
Shared HTTP utilities used across all agents.
"""

from collections import OrderedDict
import logging
import time
import yaml
import os
import requests

logger = logging.getLogger("specter.http")

# Suppress SSL warnings for pentest use
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_scan_config() -> dict:
    if os.path.exists("config.yaml"):
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f)
            return cfg.get("scan", {})
    return {}


class HTTPClient:
    def __init__(self):
        cfg = load_scan_config()
        # Simple in‑memory LRU cache (max 100 entries)
        self._cache = {}
        self._cache_capacity = 100

        self.session = requests.Session()
        self.session.verify        = cfg.get("verify_ssl", False)
        self.session.max_redirects = 10 if cfg.get("follow_redirects", True) else 0
        self.delay      = cfg.get("request_delay", 0.5)
        self.user_agent = cfg.get("user_agent", "SPECTER-Scanner/1.0")
        self.session.headers.update({"User-Agent": self.user_agent})

    def capture_baseline(self, url: str) -> dict:
        """Perform a clean request and return baseline distribution and structural entropy."""
        from core.entropy import calculate_distribution
        from core.structural_entropy import StructuralAnalyzer

        resp = self.get(url)
        if not resp:
            return {}

        return {
            "char_dist": calculate_distribution(resp.text),
            "tag_entropy": StructuralAnalyzer.analyze_html(resp.text),
            "body_length": len(resp.text)
        }

    def get(self, url: str, **kwargs) -> requests.Response | None:
        # Build cache key – URL plus sorted kwargs (excluding stream, timeout etc.)
        cache_key = ("GET", url, tuple(sorted(kwargs.items())))
        if cache_key in self._cache:
            # Move to end to mark as recently used
            self._cache[cache_key] = self._cache.pop(cache_key)  # Move to end
            logger.debug(f"Cache hit for GET {url}")
            return self._cache[cache_key]
        time.sleep(self.delay)
        try:
            resp = self.session.get(url, timeout=10, **kwargs)
            # Store in cache (store response object; shallow copy may be fine)
            self._cache[cache_key] = resp
            # Enforce capacity
            if len(self._cache) > self._cache_capacity:
                # Remove the first item (oldest)
                first_key = next(iter(self._cache))
                self._cache.pop(first_key)
            return resp
        except Exception as e:
            logger.debug(f"GET {url} failed: {e}")
            return None

    def post(self, url: str, data=None, json=None, **kwargs) -> requests.Response | None:
        time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, json=json, timeout=10, **kwargs)
        except Exception as e:
            logger.debug(f"POST {url} failed: {e}")
            return None

    def get_headers(self, url: str) -> dict:
        """Fetch response headers as a plain dict."""
        resp = self.get(url)
        if resp is None:
            return {}
        return {
            "status_code": resp.status_code,
            "url":         resp.url,
            "headers":     dict(resp.headers),
            "body_length": len(resp.text),
        }

    def get_links(self, url: str) -> list[str]:
        """Extract all href links from a page."""
        from bs4 import BeautifulSoup
        resp = self.get(url)
        if not resp:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("http"):
                links.append(href)
            elif href.startswith("/"):
                from urllib.parse import urlparse
                base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                links.append(base + href)
        return list(set(links))

    def get_forms(self, url: str) -> list[dict]:
        """Extract all forms from a page."""
        from bs4 import BeautifulSoup
        resp = self.get(url)
        if not resp:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name":  inp.get("name", ""),
                    "type":  inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append({
                "action": form.get("action", url),
                "method": form.get("method", "get").upper(),
                "inputs": inputs,
            })
        return forms
