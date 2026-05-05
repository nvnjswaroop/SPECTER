"""
SPECTER Session Manager
Saves scan progress to disk. Resume interrupted pentests.
"""

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger("specter.session")


class SessionManager:
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = session_dir
        os.makedirs(session_dir, exist_ok=True)

    def new(self, target: str, agents: list) -> dict:
        sid = datetime.now().strftime("%Y%m%d_%H%M%S")
        session = {
            "id":               sid,
            "target":           target,
            "agents_planned":   agents,
            "agents_completed": [],
            "started":          datetime.now().isoformat(),
            "finished":         None,
            "status":           "running",
            "findings":         [],
            "baselines":         {},
            "stats": {
                "critical": 0, "high": 0,
                "medium":   0, "low":  0, "info": 0
            }
        }
        self._save(session)
        logger.info(f"New session: {sid}")
        return session

    def update(self, session: dict, findings: list, agent_name: str):
        dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        session["findings"].extend(dicts)
        for f in dicts:
            sev = f.get("severity", "INFO").lower()
            session["stats"][sev] = session["stats"].get(sev, 0) + 1
        if agent_name not in session["agents_completed"]:
            session["agents_completed"].append(agent_name)
        self._save(session)

    def complete(self, session: dict):
        session["status"]   = "complete"
        session["finished"] = datetime.now().isoformat()
        self._save(session)

    def fail(self, session: dict, reason: str):
        session["status"] = f"failed: {reason}"
        self._save(session)

    def save_baseline(self, session: dict, url: str, baseline_data: dict):
        """Save a baseline distribution for a specific URL."""
        if "baselines" not in session:
            session["baselines"] = {}
        session["baselines"][url] = baseline_data
        self._save(session)

    def get_baseline(self, session: dict, url: str) -> dict | None:
        """Retrieve baseline distribution for a specific URL."""
        return session.get("baselines", {}).get(url)

    def _save(self, session: dict):
        """Save session to disk as JSON."""
        path = os.path.join(self.session_dir, f"{session['id']}.json")
        with open(path, "w") as f:
            json.dump(session, f, indent=2)

    def load(self, session_id: str) -> dict | None:
        path = os.path.join(self.session_dir, f"{session_id}.json")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    def list_all(self) -> list:
        sessions = []
        for fname in os.listdir(self.session_dir):
            if fname.endswith(".json"):
                with open(os.path.join(self.session_dir, fname)) as f:
                    try:
                        sessions.append(json.load(f))
                    except Exception:
                        pass
        return sorted(sessions, key=lambda x: x.get("started", ""), reverse=True)
