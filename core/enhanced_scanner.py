"""
SPECTER Enhanced Scanning Module
Advanced scanning with coordination and learning capabilities
"""

import logging
import concurrent.futures
from core.coordinator import AgentCoordinator
from core.knowledge_base import KnowledgeBase

logger = logging.getLogger("specter.enhanced_scanner")

class EnhancedScanner:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.coordinator = AgentCoordinator(target, config)
        self.knowledge_base = KnowledgeBase()

    def run_enhanced_scan(self, agents_to_run, threads=1):
        """Run an enhanced scan with coordination and learning"""
        # Initialize coordinator
        for agent_name in agents_to_run:
            self.coordinator.register_agent(agent_name)

        # Plan the attack sequence
        attack_plan = self.coordinator.plan_attack_sequence(agents_to_run)

        # Execute the plan
        all_findings = []

        # Run sequential agents first
        for agent_name in attack_plan["sequence"]:
            findings = self.run_single_agent(agent_name)
            all_findings.extend(findings)
            self.coordinator.share_findings(agent_name, findings)

        # Run parallel agents
        if attack_plan["parallel_groups"]:
            for agent_group in attack_plan["parallel_groups"]:
                group_findings = self.run_parallel_agents(agent_group, threads)
                all_findings.extend(group_findings)

        return all_findings

    def run_single_agent(self, agent_name):
        """Run a single agent"""
        self.coordinator.start_agent(agent_name)
        # This would actually instantiate and run the agent
        findings = []  # Placeholder for actual findings
        self.coordinator.complete_agent(agent_name, findings)
        return findings

    def run_parallel_agents(self, agent_names, threads):
        """Run multiple agents in parallel"""
        all_findings = []

        if threads > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_agent = {
                    executor.submit(self.run_single_agent, name): name
                    for name in agent_names
                }
                for future in concurrent.futures.as_completed(future_to_agent):
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        logger.error(f"Error running agent: {e}")
        else:
            # Run sequentially
            for agent_name in agent_names:
                findings = self.run_single_agent(agent_name)
                all_findings.extend(findings)

        return all_findings

# Enhanced session manager that uses the coordinator
class EnhancedSessionManager:
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = session_dir
        # Initialize with coordinator
        self.coordinator = AgentCoordinator("dummy_target", {})

    def update_with_intel(self, session: dict, findings: list, agent_name: str):
        """Update session with findings and share with coordinator"""
        # Update session as before
        dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        session["findings"].extend(dicts)
        for f in dicts:
            sev = f.get("severity", "INFO").lower()
            session["stats"][sev] = session["stats"].get(sev, 0) + 1
        if agent_name not in session["agents_completed"]:
            session["agents_completed"].append(agent_name)

        # Share findings with coordinator
        self.coordinator.share_findings(agent_name, findings)
        self._save(session)