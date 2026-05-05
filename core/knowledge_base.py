"""
SPECTER Knowledge Base
Centralized learning system for vulnerability patterns and successful techniques
"""

import json
import os
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("specter.knowledge_base")

class KnowledgeBase:
    def __init__(self, storage_path="knowledge/"):
        self.storage_path = storage_path
        self.knowledge_file = os.path.join(storage_path, "knowledge.json")
        self.findings_history = defaultdict(list)
        self.payload_success_rates = defaultdict(lambda: defaultdict(int))
        self.technology_vulnerability_map = defaultdict(list)
        self.agent_performance = defaultdict(lambda: {"scans": 0, "findings": 0})

        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)

        # Load existing knowledge if available
        self.load_knowledge()

    def record_finding(self, agent_name, vulnerability_type, payload, success=True, target_tech=None):
        """Record a finding for future learning"""
        finding_record = {
            "agent": agent_name,
            "type": vulnerability_type,
            "payload": payload,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "target_tech": target_tech
        }

        self.findings_history[agent_name].append(finding_record)

        # Update success rates
        if success:
            self.payload_success_rates[payload][vulnerability_type] += 1
        else:
            self.payload_success_rates[payload][vulnerability_type] -= 1

        # Save knowledge
        self.save_knowledge()

    def get_successful_payloads(self, target_tech, vulnerability_type):
        """Get previously successful payloads for a specific technology and vulnerability type"""
        # This would return payloads that have worked well for similar targets
        return []

    def get_optimal_approach(self, target_context):
        """Get optimal scanning approach based on target context"""
        # This would analyze target context and return best approach
        return {}

    def update_agent_performance(self, agent_name, findings_count, scan_duration):
        """Update performance metrics for an agent"""
        self.agent_performance[agent_name]["scans"] += 1
        self.agent_performance[agent_name]["findings"] += findings_count

    def save_knowledge(self):
        """Save knowledge to persistent storage"""
        try:
            knowledge_data = {
                "findings_history": dict(self.findings_history),
                "payload_success_rates": dict(self.payload_success_rates),
                "agent_performance": dict(self.agent_performance),
                "last_updated": datetime.now().isoformat()
            }

            # Create knowledge directory if it doesn't exist
            os.makedirs(os.path.dirname(self.knowledge_file) if os.path.dirname(self.knowledge_file) else ".", exist_ok=True)

            with open(self.knowledge_file, 'w') as f:
                json.dump(knowledge_data, f, indent=2)

            logger.info("Knowledge base saved successfully")
        except Exception as e:
            logger.error(f"Failed to save knowledge base: {e}")

    def load_knowledge(self):
        """Load existing knowledge from storage"""
        try:
            if os.path.exists(self.knowledge_file):
                with open(self.knowledge_file, 'r') as f:
                    knowledge_data = json.load(f)

                # Load findings history
                if "findings_history" in knowledge_data:
                    self.findings_history = defaultdict(list, knowledge_data["findings_history"])

                # Load payload success rates
                if "payload_success_rates" in knowledge_data:
                    self.payload_success_rates = defaultdict(
                        lambda: defaultdict(int),
                        knowledge_data["payload_success_rates"]
                    )

                # Load agent performance
                if "agent_performance" in knowledge_data:
                    self.agent_performance = defaultdict(
                        lambda: {"scans": 0, "findings": 0},
                        knowledge_data["agent_performance"]
                    )

                logger.info("Knowledge base loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")

    def get_agent_performance(self, agent_name):
        """Get performance metrics for a specific agent"""
        return self.agent_performance[agent_name]

    def suggest_optimal_payloads(self, target_tech):
        """Suggest payloads that have been successful against similar technologies"""
        # This would analyze the knowledge base and suggest optimal payloads
        return []