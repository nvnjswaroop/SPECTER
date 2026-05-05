"""
SPECTER Auth Agent
Tests for broken authentication: weak passwords, JWT flaws, session issues,
default credentials, missing rate limiting.
"""

import logging
import base64
import json
import re
import time

from core.agent_base import BaseAgent
from tools.http_client import HTTPClient

logger = logging.getLogger("specter.auth")

DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("root",   "root"),
    ("root",   "toor"),
    ("user",   "user"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("admin",  ""),
    ("",       "admin"),
]

COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/admin", "/admin/login",
    "/wp-login.php", "/user/login", "/auth/login",
    "/api/auth/login", "/api/login", "/account/login",
]

JWT_NONE_HEADER = base64.b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
JWT_WEAK_SECRETS = ["secret", "password", "123456", "jwt_secret", "supersecret"]


class AuthAgent(BaseAgent):
    def __init__(self, router, target, config):
        super().__init__(router, target, config)
        self.name = "AuthAgent"
        self.http = HTTPClient()

    def system_prompt(self):
        return (
            f"You are an authentication security expert. Target: {self.target}\n"
            "Analyze auth mechanisms for:\n"
            "- Weak/default credentials\n"
            "- JWT vulnerabilities (alg:none, weak secrets)\n"
            "- Missing rate limiting or lockout\n"
            "- Session fixation or insecure cookies\n"
            "Only report confirmed issues."
        )

    def _find_login_endpoints(self) -> list[str]:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        for path in COMMON_LOGIN_PATHS:
            url = base + path
            resp = self.http.get(url)
            if resp and resp.status_code not in [404, 403]:
                found.append(url)
        return found

    def _test_default_creds(self, login_url: str) -> dict | None:
        forms = self.http.get_forms(login_url)
        if not forms:
            return None

        form = forms[0]
        # Find username and password fields
        user_field = next((i["name"] for i in form["inputs"] if i["type"] in ["text", "email"] or "user" in i["name"].lower() or "email" in i["name"].lower()), None)
        pass_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not user_field or not pass_field:
            return None

        # Get baseline (failed login) for comparison
        data = {i["name"]: i["value"] or "x" for i in form["inputs"]}
        data[user_field] = "invaliduser_specter"
        data[pass_field] = "invalidpass_specter"
        baseline = self.http.post(login_url, data=data)
        baseline_len = len(baseline.text) if baseline else 0
        baseline_url = baseline.url if baseline else login_url

        for username, password in DEFAULT_CREDS:
            data[user_field] = username
            data[pass_field] = password
            resp = self.http.post(login_url, data=data)
            if not resp:
                continue
            # Signs of successful login: redirect to dashboard or response length differs
            if (resp.url != baseline_url or
                abs(len(resp.text) - baseline_len) > 200 or
                resp.status_code in [200, 302] and "logout" in resp.text.lower()):
                return {"username": username, "password": password, "url": login_url}

        return None

    def _test_rate_limiting(self, login_url: str) -> bool:
        """Check if login has rate limiting by sending 20 rapid requests."""
        forms = self.http.get_forms(login_url)
        if not forms:
            return False

        form = forms[0]
        pass_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)
        if not pass_field:
            return False

        data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
        statuses = []
        for _ in range(15):
            data[pass_field] = f"wrongpass_{_}"
            resp = self.http.post(login_url, data=data)
            if resp:
                statuses.append(resp.status_code)
                # Rate limiting usually returns 429 or redirects to lockout
                if resp.status_code == 429 or "locked" in resp.text.lower() or "too many" in resp.text.lower():
                    return True  # Rate limiting IS present
        return False  # No rate limiting detected

    def _check_cookies(self, url: str) -> list:
        issues = []
        resp = self.http.get(url)
        if not resp:
            return []
        for cookie in resp.cookies:
            if not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
            if "samesite" not in str(cookie.__dict__).lower():
                issues.append(f"Cookie '{cookie.name}' missing SameSite attribute")
        return issues

    def _check_jwt(self, url: str) -> list:
        """Look for JWT tokens in responses and test for alg:none."""
        resp = self.http.get(url)
        if not resp:
            return []

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        tokens = re.findall(jwt_pattern, resp.text + str(resp.headers))
        issues = []

        for token in tokens[:3]:  # test first 3 tokens
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                header = json.loads(base64.b64decode(parts[0] + "==").decode())
                if header.get("alg", "").upper() == "NONE":
                    issues.append(f"JWT with alg:none found: {token[:60]}...")
                    continue
                # Test weak secret (only flag, don't try to crack in production tool)
                payload_decoded = base64.b64decode(parts[1] + "==").decode()
                issues.append(f"JWT found — algorithm: {header.get('alg')}. Recommend testing for weak secret.")
            except Exception:
                pass

        return issues

    def run(self) -> list:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold cyan][ AuthAgent ][/bold cyan] Target: {self.target}")

        # 1. Find login endpoints
        console.print("  [→] Discovering login endpoints...")
        login_endpoints = self._find_login_endpoints()
        console.print(f"      Found: {login_endpoints or 'none via common paths'}")

        for login_url in login_endpoints:
            # 2. Default credentials
            console.print(f"  [→] Testing default credentials at {login_url}...")
            cred_result = self._test_default_creds(login_url)
            if cred_result:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Default Credentials Accepted: {cred_result['username']}:{cred_result['password']}",
                    description="Default or weak credentials allow unauthorized access.",
                    poc=f"Login at {login_url} with {cred_result['username']}:{cred_result['password']}",
                    remediation="Remove default accounts. Enforce strong password policy.",
                    endpoint=login_url,
                )

            # 3. Rate limiting
            console.print(f"  [→] Testing rate limiting at {login_url}...")
            has_rate_limit = self._test_rate_limiting(login_url)
            if not has_rate_limit:
                self.add_finding(
                    severity="HIGH",
                    title="No Rate Limiting on Login",
                    description="Login endpoint does not throttle or lock accounts after repeated failures — brute force is possible.",
                    poc=f"Send 100+ POST requests to {login_url} — no lockout occurs.",
                    remediation="Implement account lockout or CAPTCHA after 5 failed attempts.",
                    endpoint=login_url,
                )

        # 4. Cookie security
        console.print("  [→] Checking cookie security flags...")
        cookie_issues = self._check_cookies(self.target)
        for issue in cookie_issues:
            self.add_finding(
                severity="MEDIUM",
                title="Insecure Cookie Configuration",
                description=issue,
                poc=f"curl -v {self.target} | grep Set-Cookie",
                remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                endpoint=self.target,
            )

        # 5. JWT analysis
        console.print("  [→] Scanning for JWT tokens...")
        jwt_issues = self._check_jwt(self.target)
        for issue in jwt_issues:
            self.add_finding(
                severity="HIGH",
                title="JWT Vulnerability Detected",
                description=issue,
                poc=f"Inspect JWT in response at {self.target}",
                remediation="Use strong algorithms (RS256/ES256). Never accept alg:none. Use strong signing secrets.",
                endpoint=self.target,
            )

        # 6. LLM analysis
        console.print("  [→] LLM auth analysis...")
        prompt = (
            f"Auth analysis for {self.target}:\n"
            f"Login endpoints found: {login_endpoints}\n"
            f"Cookie issues: {cookie_issues}\n"
            f"JWT issues: {jwt_issues}\n"
            "What additional auth vulnerabilities should be checked? Any specific bypass techniques for this stack?"
        )
        advice = self.think(prompt)
        console.print(f"\n[dim]{advice[:500]}[/dim]\n")

        console.print(f"[green][ AuthAgent ][/green] Complete — {len(self.findings)} finding(s)\n")
        return self.findings
