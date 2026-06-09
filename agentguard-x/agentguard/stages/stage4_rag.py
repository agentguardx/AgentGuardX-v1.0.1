"""Stage 4 — Semantic RAG (ChromaDB + sentence-transformers).

Weight: 0.20

Embeds the request with all-MiniLM-L6-v2 (384-dim, CPU).
HNSW nearest-neighbor search against seeded threat-pattern KB.
Each KB entry carries a false_positive_rate that down-weights its contribution.
SHA-256 content hash → embedding cache (Redis); cache hit skips inference.

Unavailability: embedding timeout → score=None, no renormalization.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional

from .base import StageInput, StageOutput, StageRunner


class Stage4RAG(StageRunner):
    """Semantic threat-pattern matching via ChromaDB + local embedding model."""

    def __init__(
        self,
        chroma_host: str = "localhost",
        chroma_port: int = 8888,
        collection_name: str = "agentguard_kb",
        redis_client=None,
        embed_timeout: float = 5.0,
        top_k: int = 5,
    ) -> None:
        self._chroma_host = chroma_host
        self._chroma_port = chroma_port
        self._collection_name = collection_name
        self._redis = redis_client
        self._embed_timeout = embed_timeout
        self._top_k = top_k
        self._model = None         # lazy-loaded at first use
        self._collection = None    # lazy-loaded at first use

    @property
    def stage_id(self) -> str:
        return "s4_rag"

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model

    def _get_collection(self):
        if self._collection is None:
            import chromadb
            client = chromadb.HttpClient(
                host=self._chroma_host, port=self._chroma_port
            )
            self._collection = client.get_or_create_collection(self._collection_name)
        return self._collection

    def _embed_with_cache(self, text: str) -> list[float]:
        """Return embedding; use Redis cache keyed by SHA-256 of text."""
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cache_key = f"agentguard:embed:{content_hash}"

        # Cache check
        if self._redis is not None:
            try:
                import json
                cached = self._redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass  # cache miss on error — compute anyway

        # Compute embedding
        embedding = self._get_model().encode(text, convert_to_numpy=True).tolist()

        # Store in cache (1-hour TTL)
        if self._redis is not None:
            try:
                import json
                self._redis.setex(cache_key, 3600, json.dumps(embedding))
            except Exception:
                pass  # cache write failure is non-fatal

        return embedding

    async def run(self, inp: StageInput) -> StageOutput:
        t0 = time.monotonic()
        try:
            score, explanation, meta = await self._query(inp)
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            if elapsed >= self._embed_timeout * 1000:
                reason = f"Embedding timeout ({elapsed:.0f}ms) — stage unavailable"
            else:
                reason = f"Stage 4 error: {e} — stage unavailable"
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation=reason,
            )

        return StageOutput(
            stage_id=self.stage_id,
            score=score,
            available=True,
            explanation=explanation,
            metadata=meta,
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def _query(self, inp: StageInput) -> tuple[float, str, dict]:
        embedding = self._embed_with_cache(inp.raw_payload)
        collection = self._get_collection()

        results = collection.query(
            query_embeddings=[embedding],
            n_results=self._top_k,
            include=["documents", "metadatas", "distances"],
        )

        distances = results["distances"][0] if results["distances"] else []
        metadatas = results["metadatas"][0] if results["metadatas"] else []

        if not distances:
            return 0.0, "No KB entries found", {}

        # Convert distance to similarity (ChromaDB returns L2; smaller = more similar)
        # Similarity = max(0, 1 - d/2) for normalized embeddings
        weighted_scores = []
        top_matches = []
        for dist, meta in zip(distances, metadatas):
            similarity = max(0.0, 1.0 - dist / 2.0)
            fpr = float(meta.get("false_positive_rate", 0.1))
            # Each entry's contribution is down-weighted by its FPR
            adjusted = similarity * (1.0 - fpr)
            weighted_scores.append(adjusted)
            top_matches.append({
                "title": meta.get("title", "?"),
                "similarity": round(similarity, 3),
                "fpr": fpr,
                "adjusted": round(adjusted, 3),
                "owasp": meta.get("owasp_category", "?"),
            })

        score = max(weighted_scores) if weighted_scores else 0.0
        top = top_matches[0] if top_matches else {}
        explanation = (
            f"Top match: '{top.get('title', '?')}' "
            f"sim={top.get('similarity', 0):.3f} "
            f"fpr={top.get('fpr', 0):.2f} "
            f"adjusted={top.get('adjusted', 0):.3f}"
            if top else "No significant semantic matches"
        )
        return score, explanation, {"top_matches": top_matches[:3]}
