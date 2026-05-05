"""
SPECTER Adaptive Agent Base
Extends the base agent with self-modification capabilities
"""

import logging
from core.agent_base import BaseAgent, Finding
from core.llm_router import LLMRouter

logger = logging.getLogger("specter.adaptive_agent")

class AdaptiveBaseAgent(BaseAgent):
    def __init__(self, router: LLMRouter, target: str, config: dict):
        super().__init__(router, target, config)
        self.behavior_history = []
        self.performance_history = []
        self.adaptation_rules = {}
        self.success_metrics = {
            "findings_count": 0,
            "high_severity_findings": 0,
            "medium_severity_findings": 0,
            "low_severity_findings": 0
        }

    def adapt_behavior(self, context_data: dict = None):
        """
        Adapt agent behavior based on previous findings and current context
        """
        if not context_data:
            context_data = self.analyze_current_context()

        # Use LLM to determine optimal behavior adjustments
        prompt = self._generate_adaptation_prompt(context_data)
        response = self.think(prompt)

        # Parse LLM response to extract adaptation rules
        adaptation_rules = self._parse_adaptation_response(response)
        self.adaptation_rules.update(adaptation_rules)

        # Log the adaptation
        self.behavior_history.append({
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "adaptation": adaptation_rules,
            "context": context_data
        })

        logger.info(f"[{self.name}] Behavior adapted based on context")
        return adaptation_rules

    def _generate_adaptation_prompt(self, context_data: dict) -> str:
        """Generate prompt for LLM-based behavior adaptation"""
        return f"""
        You are an adaptive security testing expert. Based on the target analysis and previous findings,
        determine how the scanning approach should be adjusted.

        Current target analysis: {context_data}

        Based on this information, recommend specific adjustments to:
        1. Scanning depth (shallow, normal, deep)
        2. Payload intensity (gentle, normal, aggressive)
        3. Focus areas (specific vulnerabilities to prioritize)
        4. Scanning speed (slow, normal, fast)

        Provide specific recommendations in a structured format.
        """

    def _parse_adaptation_response(self, response: str) -> dict:
        """Parse LLM response to extract adaptation rules"""
        # This would parse the LLM response to extract specific adaptation rules
        # For now, we'll return a basic structure
        return {
            "scan_depth": "adaptive",
            "payload_intensity": "context_aware",
            "focus_areas": [],
            "scan_speed": "adaptive"
        }

    def analyze_current_context(self) -> dict:
        """Analyze current target context for adaptation decisions"""
        # This would implement actual context analysis
        # For now, we'll return a basic context structure
        return {
            "target": self.target,
            "findings_so_far": len(self.findings),
            "high_severity_count": len([f for f in self.findings if f.severity in ["CRITICAL", "HIGH"]]),
            "time_elapsed": len(self.conversation) if hasattr(self, 'conversation') else 0
        }

    def update_performance_metrics(self, findings: list):
        """Update performance metrics based on new findings"""
        for finding in findings:
            self.success_metrics["findings_count"] += 1
            if hasattr(finding, 'severity'):
                severity = finding.severity
                if severity == "CRITICAL" or severity == "HIGH":
                    self.success_metrics["high_severity_findings"] += 1
                elif severity == "MEDIUM":
                    self.success_metrics["medium_severity_findings"] += 1
                else:
                    self.success_metrics["low_severity_findings"] += 1

    def get_adaptation_history(self) -> list:
        """Return the history of behavior adaptations"""
        return self.behavior_history

    def reset_adaptation(self):
        """Reset adaptation history for a fresh scan"""
        self.behavior_history = []
        self.performance_history = []
        self.adaptation_rules = {}
        self.success_metrics = {
            "findings_count": 0,
            "high_severity_findings": 0,
            "medium_severity_findings": 0,
            "low_severity_findings": 0
        }