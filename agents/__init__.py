# SPECTER agents

# Global registry for plug‑in agents
_AGENT_REGISTRY = {}

def register_agent(name: str):
    """Decorator to register an agent class under a given name."""
    def decorator(cls):
        _AGENT_REGISTRY[name] = cls
        return cls
    return decorator

def get_registered_agents():
    """Return a copy of the current agent registry dictionary."""
    return dict(_AGENT_REGISTRY)

