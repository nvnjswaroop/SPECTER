"""
LFI (Local File Inclusion) Agent for SPECTER.
Performs a simple check for typical traversal patterns in the response body.
"""
import logging
from urllib.parse import urljoin

from core.agent_base import BaseAgent, Finding
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.lfi")

class LFIAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "LFIAgent"
        self.http = HTTPClient()

    def run(self) -> list[Finding]:
        logger.info(f"[LFIAgent] Scanning {self.target}")
        resp = self.http.get(self.target)
        if not resp:
            return self.findings
        body = resp.text.lower()
        # Simple heuristic: look for directory‑traversal payloads echoed back
        traversal_markers = ["../etc/passwd", "..%2f..%2fetc%2fpasswd", "..\\..\\etc\\passwd"]
        for marker in traversal_markers:
            if marker in body:
                self.add_finding(
                    severity="HIGH",
                    title="Potential LFI / Directory Traversal",
                    description=f"Response contains the traversal string '{marker}'.",
                    poc=f"curl '{self.target}?file=../etc/passwd'",
                    remediation="Validate and sanitize any file path parameters. Use allow‑list of files.",
                    endpoint=self.target,
                )
                break
        return self.findings
