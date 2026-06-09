"""Cognitive gateway — LangChain callback hooks + query interceptor.

Hooks (AgentGuardCallbackHandler) require langchain-core; imported lazily
so that the rest of the gateway (IntentGate, PostHookProcessor, etc.)
can be used and tested without langchain installed.
"""

from .intent_gate import IntentGate
from .query_interceptor import QueryInterceptor
from .post_hook import PostHookProcessor


def get_callback_handler(*args, **kwargs):
    """Lazy import AgentGuardCallbackHandler (requires langchain-core)."""
    from .hooks import AgentGuardCallbackHandler
    return AgentGuardCallbackHandler(*args, **kwargs)


__all__ = [
    "IntentGate",
    "QueryInterceptor",
    "PostHookProcessor",
    "get_callback_handler",
]
