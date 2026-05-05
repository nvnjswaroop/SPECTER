"""
SPECTER Agent Base
All 5 agents inherit from this. Provides shared: LLM chat, finding logging,
conversation history, and structured output.
"""

import logging
from datetime import datetime
from core.llm_router import LLMRouter

logger = logging.getLogger("specter.agent")


class Finding:
    SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, agent: str, severity: str, title: str,
                 description: str, poc: str = "", remediation: str = "",
                 endpoint: str = ""):
        assert severity in self.SEVERITIES, f"Invalid severity: {severity}"
        self.agent       = agent
        self.severity    = severity
        self.title       = title
        self.description = description
        self.poc         = poc            # proof-of-concept command or payload
        self.remediation = remediation
        self.endpoint    = endpoint
        self.timestamp   = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return self.__dict__

    def severity_emoji(self) -> str:
        return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW":  "🟢", "INFO": "⚪"}.get(self.severity, "⚪")


class BaseAgent:
    def __init__(self, router: LLMRouter, target: str, config: dict):
        # Initialization (duplicate block removed)
        self.router      = router
        self.target      = target
        self.config      = config
        self.name        = "BaseAgent"
        self.findings    : list[Finding] = []
        self.conversation: list[dict]    = []
        self.max_rounds  = config.get("max_rounds", 10)
        self.session = None  # Add session attribute

    # ------------------------------------------------------------------
    def system_prompt(self) -> str:
        """Override in subclasses."""
        return (
            f"You are a professional penetration tester auditing: {self.target}\n"
            "Report only confirmed vulnerabilities with working proof-of-concept.\n"
            "Be concise and technical."
        )

    def think(self, user_message: str) -> str:
        """One turn of reasoning with the LLM."""
        self.conversation.append({"role": "user", "content": user_message})
        response = self.router.chat(
            messages=self.conversation,
            system_prompt=self.system_prompt()
        )
        self.conversation.append({"role": "assistant", "content": response})
        logger.debug(f"[{self.name}] LLM: {response[:200]}")
        return response

    def reset_conversation(self):
        """Clear history for a fresh sub-task."""
        self.conversation = []

    # ------------------------------------------------------------------
    def add_finding(self, severity: str, title: str, description: str,
                    poc: str = "", remediation: str = "", endpoint: str = ""):
        f = Finding(self.name, severity, title, description, poc, remediation, endpoint)
        self.findings.append(f)
        # Update confidence based on any entropy metrics present in findings
        entropies = [getattr(find, "entropy_avg", 0.0) for find in self.findings]
        if entropies:
            # Average of non‑zero entropy values (fallback to 0 if none provided)
            non_zero = [e for e in entropies if e > 0]
            self.confidence = sum(non_zero) / len(non_zero) if non_zero else 0.0
        logger.info(f"[{self.name}] [{severity}] {title}")
        return f

    # ------------------------------------------------------------------
    def run(self) -> list[Finding]:
        """Override in each agent. Returns list of Finding objects."""
        raise NotImplementedError

    def summary(self) -> str:
        if not self.findings:
            return f"[{self.name}] No findings."
        lines = [f"[{self.name}] {len(self.findings)} finding(s):"]
        for f in self.findings:
            lines.append(f"  {f.severity_emoji()} [{f.severity}] {f.title}")
        return "\n".join(lines)
