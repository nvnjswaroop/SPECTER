"""
SPECTER Adaptive Recon Agent
Enhanced recon agent with self-modification capabilities
"""

import subprocess
import logging
from urllib.parse import urlparse
from core.agent_base import BaseAgent
from core.adaptive_agent import AdaptiveBaseAgent
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.adaptive_recon")

# Security headers to check for
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS missing - allows downgrade attacks"),
    ("Content-Security-Policy", "CSP missing - increases XSS risk"),
    ("X-Frame-Options", "Clickjacking protection missing"),
    ("X-Content-Type-Options", "MIME sniffing protection missing"),
    ("Referrer-Policy", "Referrer policy not set"),
    ("Permissions-Policy", "Permissions policy not configured"),
]

class AdaptiveReconAgent(AdaptiveBaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "AdaptiveReconAgent"
        self.http = HTTPClient()
        self.technology_profile = {}
        self.vulnerability_surface = []

    def system_prompt(self):
        context = self.analyze_current_context()
        adaptation_rules = self.adaptation_rules if self.adaptation_rules else "Initial scan"

        return (
            f"You are an expert adaptive recon pentester. Target: {self.target}\n"
            f"Current context analysis: {context}\n"
            f"Adaptation rules: {adaptation_rules}\n\n"
            "Given raw scan data, identify:\n"
            "1. Technology stack (framework, server, language, CMS)\n"
            "2. Interesting endpoints or parameters\n"
            "3. Security misconfigurations\n"
            "4. Top attack vectors to pursue next\n"
            "Be concise, technical, and structured. Focus on high-value targets first."
        )

    def run(self) -> list:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold cyan][ AdaptiveReconAgent ][/bold cyan] Target: {self.target}")

        # Adapt behavior based on initial context
        self.adapt_behavior()

        # 1. HTTP headers
        console.print("  [→] Fetching HTTP response...")
        resp = self.http.get(self.target)
        header_data = {}
        body_preview = ""
        if resp:
            header_data = dict(resp.headers)
            body_preview = resp.text[:3000]
            console.print(f"      Status: {resp.status_code}")
        else:
            console.print("      [red]Could not reach target.[/red]")

        # 2. Nmap
        console.print("  [→] Port scanning with nmap...")
        nmap_out = self._nmap_scan()

        # 3. Enumerate links
        console.print("  [→] Enumerating links...")
        links = self.http.get_links(self.target)
        console.print(f"      Found {len(links)} links")

        # 4. Technology detection
        tech = self._detect_tech(header_data, body_preview)
        if tech:
            console.print(f"      Tech stack: {', '.join(tech)}")
            self.technology_profile = {"detected_tech": tech}

        # 5. Security header audit
        missing_headers = self._check_security_headers(header_data)
        for header, desc in missing_headers:
            self.add_finding(
                severity="MEDIUM",
                title=f"Missing Header: {header}",
                description=desc,
                poc=f"curl -I {self.target}",
                remediation=f"Add the '{header}' response header.",
                endpoint=self.target,
            )

        # 6. LLM analysis with adaptation
        console.print("  [→] LLM analysis with adaptation...")
        prompt = (
            f"Recon data for {self.target}:\n\n"
            f"HTTP HEADERS:\n{header_data}\n\n"
            f"DETECTED TECH: {tech}\n\n"
            f"NMAP:\n{nmap_out[:2000]}\n\n"
            f"SAMPLE LINKS: {links[:20]}\n\n"
            f"ADAPTATION CONTEXT: {self.adaptation_rules}\n\n"
            "Summarize the attack surface and list the top 5 most promising attack vectors "
            "with priority based on the adaptation context."
        )
        analysis = self.think(prompt)
        console.print(f"\n[dim]{analysis[:800]}[/dim]\n")

        # Update performance metrics
        self.update_performance_metrics(self.findings)

        console.print(f"[green][ AdaptiveReconAgent ][/green] Complete - {len(self.findings)} finding(s)\n")
        return self.findings

    def _nmap_scan(self) -> str:
        host = urlparse(self.target).hostname or self.target

        # Validate hostname to prevent command injection
        if not self._is_valid_hostname(host):
            return "Invalid hostname for nmap scan"

        try:
            result = subprocess.run(
                ["nmap", "-sV", "--top-ports", "200", "-T4", "--open", host],
                capture_output=True, text=True, timeout=90
            )
            return result.stdout or result.stderr or "No nmap output."
        except FileNotFoundError:
            return "nmap not installed - install with: sudo apt install nmap (Linux) or choco install nmap (Windows)"
        except subprocess.TimeoutExpired:
            return "nmap timed out after 90 seconds."
        except Exception as e:
            return f"nmap error: {e}"

    def _check_security_headers(self, headers: dict) -> list:
        missing = []
        for header, desc in SECURITY_HEADERS:
            if header not in headers:
                missing.append((header, desc))
        return missing

    def _detect_tech(self, response_headers: dict, body_preview: str) -> list:
        tech = []
        server = response_headers.get("Server", "")
        powered = response_headers.get("X-Powered-By", "")
        if server:
            tech.append(f"Server: {server}")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
        # Common framework fingerprints
        fingerprints = {
            "wp-content": "WordPress",
            "laravel": "Laravel (PHP)",
            "django": "Django (Python)",
            "rails": "Ruby on Rails",
            "next/": "Next.js",
            "react": "React",
            "__next": "Next.js",
            "asp.net": "ASP.NET",
            "cf-ray": "Cloudflare",
        }
        combined = (body_preview + str(response_headers)).lower()
        for sig, name in fingerprints.items():
            if sig in combined:
                tech.append(name)
        return list(set(tech))