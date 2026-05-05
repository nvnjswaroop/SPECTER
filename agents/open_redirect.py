"""
Open‑Redirect Agent for SPECTER.
Looks for URL parameters that are reflected back unchanged in redirects.
"""
import logging
from urllib.parse import urlparse, parse_qs

from core.agent_base import BaseAgent, Finding
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.open_redirect")

class OpenRedirectAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "OpenRedirectAgent"
        self.http = HTTPClient()

    def _extract_params(self, url: str):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def run(self) -> list[Finding]:
        logger.info(f"[OpenRedirectAgent] Scanning {self.target}")
        params = self._extract_params(self.target)
        for p in params:
            test_url = f"{self.target}?{p}=http://evil.com"
            resp = self.http.get(test_url, allow_redirects=False)
            if resp and resp.is_redirect:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    self.add_finding(
                        severity="HIGH",
                        title="Open Redirect vulnerability",
                        description=f"Parameter '{p}' redirects to an external URL.",
                        poc=f"curl -I '{test_url}'",
                        remediation="Validate redirect URLs against a whitelist and avoid reflecting user‑controlled values.",
                        endpoint=self.target,
                    )
                    break
        return self.findings
