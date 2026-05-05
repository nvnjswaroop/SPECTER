"""
File‑Upload Agent for SPECTER.
Detects endpoints that accept multipart/form‑data uploads and attempts a harmless test upload.
"""
import logging
import io
from urllib.parse import urljoin

from core.agent_base import BaseAgent, Finding
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.file_upload")

class FileUploadAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "FileUploadAgent"
        self.http = HTTPClient()

    def _discover_endpoints(self):
        # Very naive discovery: look for common upload paths in the target URL
        common_paths = ["/upload", "/api/upload", "/file/upload", "/images/upload"]
        return [urljoin(self.target, p) for p in common_paths]

    def run(self) -> list[Finding]:
        logger.info(f"[FileUploadAgent] Scanning {self.target}")
        endpoints = self._discover_endpoints()
        for ep in endpoints:
            # Build a minimal text file in memory
            file_content = io.BytesIO(b"test file content")
            files = {"file": ("test.txt", file_content, "text/plain")}
            try:
                resp = self.http.post(ep, files=files)
            except Exception as e:
                logger.debug(f"Upload attempt failed for {ep}: {e}")
                continue
            if resp and resp.status_code in (200, 201, 204):
                self.add_finding(
                    severity="MEDIUM",
                    title="File upload endpoint detected",
                    description=f"Successfully posted a test file to {ep}.",
                    poc=f"curl -F 'file=@test.txt' {ep}",
                    remediation="Validate uploaded content, enforce file‑type checks, and store files outside the web root.",
                    endpoint=ep,
                )
        return self.findings
