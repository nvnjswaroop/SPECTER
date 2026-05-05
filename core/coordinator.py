"""
SPECTER Agent Coordinator
Centralized coordination system for multi-agent collaboration
"""

import logging
from datetime import datetime
from threading import Lock

logger = logging.getLogger("specter.coordinator")

class AgentCoordinator:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.shared_memory = {}
        self.findings = {}
        self.agent_lock = Lock()
        self.agent_status = {}
        self.agent_dependencies = {}

    def register_agent(self, agent_name):
        """Register an agent with the coordinator"""
        with self.agent_lock:
            self.agent_status[agent_name] = {
                "status": "registered",
                "start_time": None,
                "end_time": None,
                "findings": []
            }

    def start_agent(self, agent_name):
        """Mark an agent as started"""
        with self.agent_lock:
            if agent_name in self.agent_status:
                self.agent_status[agent_name]["status"] = "running"
                self.agent_status[agent_name]["start_time"] = datetime.now().isoformat()
                logger.info(f"Agent {agent_name} started")

    def complete_agent(self, agent_name, findings=None):
        """Mark an agent as completed and store findings"""
        with self.agent_lock:
            if agent_name in self.agent_status:
                self.agent_status[agent_name]["status"] = "completed"
                self.agent_status[agent_name]["end_time"] = datetime.now().isoformat()
                if findings:
                    self.agent_status[agent_name]["findings"] = findings
                logger.info(f"Agent {agent_name} completed")

    def share_findings(self, from_agent, findings):
        """Share findings between agents"""
        if from_agent not in self.findings:
            self.findings[from_agent] = []
        self.findings[from_agent].extend(findings)
        logger.info(f"Findings from {from_agent} shared with coordinator")

    def get_shared_findings(self, requesting_agent):
        """Get findings shared by other agents"""
        return self.findings.get(requesting_agent, [])

    def plan_attack_sequence(self, available_agents):
        """Plan optimal sequence of agent execution based on dependencies"""
        # Simple dependency planning:
        # 1. Recon should run first
        # 2. Other agents can run in parallel after recon
        attack_plan = {
            "sequence": [],
            "parallel_groups": []
        }

        if "recon" in available_agents or "adaptive" in available_agents:
            attack_plan["sequence"] = ["recon" if "recon" in available_agents else "adaptive"]
            other_agents = [agent for agent in available_agents if agent not in ["recon", "adaptive"]]
            if other_agents:
                attack_plan["parallel_groups"].append(other_agents)
        else:
            # If no recon agent, run all agents in parallel
            attack_plan["parallel_groups"].append(list(available_agents))

        return attack_plan

    def get_agent_status(self):
        """Get current status of all agents"""
        with self.agent_lock:
            return self.agent_status.copy()

    def get_attack_surface_intel(self):
        """Get intelligence about the attack surface from all shared findings"""
        attack_surface = {
            "endpoints": set(),
            "parameters": set(),
            "technologies": set(),
            "vulnerabilities": []
        }

        for agent_findings in self.findings.values():
            for finding in agent_findings:
                # Extract relevant information from findings
                if hasattr(finding, 'endpoint') and finding.endpoint:
                    attack_surface["endpoints"].add(finding.endpoint)
                if hasattr(finding, 'vulnerabilities') and finding.vulnerabilities:
                    attack_surface["vulnerabilities"].extend(finding.vulnerabilities)

        return attack_surface