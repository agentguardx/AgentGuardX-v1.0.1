"""Triage engine stages — each implements the StageRunner interface.

Stages 3–5 have external dependencies (httpx, chromadb, redis).
Import them lazily to keep base + scoring + S1/S2 dependency-free for unit tests.
"""

from .base import StageRunner, StageInput, StageOutput
from .stage1_identity import Stage1IdentityGate
from .stage2_signatures import Stage2Signatures


def get_stage3(opa_url: str = "http://localhost:8181"):
    from .stage3_opa import Stage3OPA
    return Stage3OPA(opa_url=opa_url)


def get_stage4(**kwargs):
    from .stage4_rag import Stage4RAG
    return Stage4RAG(**kwargs)


def get_stage5(redis_client=None):
    from .stage5_behavioral import Stage5Behavioral
    return Stage5Behavioral(redis_client=redis_client)


__all__ = [
    "StageRunner",
    "StageInput",
    "StageOutput",
    "Stage1IdentityGate",
    "Stage2Signatures",
    "get_stage3",
    "get_stage4",
    "get_stage5",
]
