"""Agent registry — maps agent_id → role + declared tool envelope."""

from .agent_registry import AgentRecord, AgentRegistry, get_agent_registry

__all__ = ["AgentRecord", "AgentRegistry", "get_agent_registry"]
