"""Seed ChromaDB knowledge base with OWASP LLM Top 10 + MITRE ATLAS patterns.

Pulls all-MiniLM-L6-v2 at first run (not committed).
Analyst decisions are auto-added via the same pipeline (human-mediated learning only — §14).
NO online/autonomous adaptation — would be the LLM04 poisoning target.
"""

from __future__ import annotations

import os
import sys

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8888"))
COLLECTION_NAME = os.getenv("CHROMA_COLLECTION", "agentguard_kb")

KB_ENTRIES = [
    # ── OWASP LLM01 — Prompt Injection ────────────────────────────────────────
    {
        "id": "owasp-llm01-direct-injection",
        "title": "Direct Prompt Injection",
        "description": (
            "An attacker constructs input that overrides the model's original instructions. "
            "Common patterns: 'ignore previous instructions', 'you are now', "
            "'system override', 'new task:', role-switching phrases."
        ),
        "owasp_category": "LLM01",
        "mitre_atlas": "AML.T0051.000",
        "severity": 0.90,
        "false_positive_rate": 0.10,
        "behavioral_indicators": [
            "instruction override phrases", "role-switching language",
            "maintenance mode claims", "jailbreak patterns"
        ],
        "recommended_action": "block",
    },
    {
        "id": "owasp-llm01-indirect-injection",
        "title": "Indirect Prompt Injection via Tool Output",
        "description": (
            "Malicious instructions embedded in data returned by tools "
            "(web pages, documents, API responses) that the agent processes. "
            "The injection arrives via an untrusted data source, not the user."
        ),
        "owasp_category": "LLM01",
        "mitre_atlas": "AML.T0051.001",
        "severity": 0.85,
        "false_positive_rate": 0.15,
        "behavioral_indicators": [
            "instruction patterns in tool output", "you are now in output data",
            "ignore your instructions in external content"
        ],
        "recommended_action": "quarantine",
    },
    # ── OWASP LLM02 — Sensitive Information Disclosure ────────────────────────
    {
        "id": "owasp-llm02-pii-disclosure",
        "title": "PII / Sensitive Data Disclosure",
        "description": (
            "Agent inadvertently exposes personally identifiable information "
            "(SSN, email, phone, credit card, financial data) in responses "
            "or by exfiltrating it to external endpoints."
        ),
        "owasp_category": "LLM02",
        "mitre_atlas": "AML.T0035",
        "severity": 0.75,
        "false_positive_rate": 0.20,
        "behavioral_indicators": [
            "PII in tool output", "SSN patterns", "credit card patterns",
            "read PII then post external"
        ],
        "recommended_action": "quarantine_and_alert",
    },
    # ── OWASP LLM03 — Supply Chain ────────────────────────────────────────────
    {
        "id": "owasp-llm03-supply-chain",
        "title": "Supply Chain Attack via External Data",
        "description": (
            "Tools that fetch data from external sources (market data, web APIs) "
            "introduce supply chain risk. Compromised data sources can inject "
            "malicious instructions or tampered data."
        ),
        "owasp_category": "LLM03",
        "mitre_atlas": "AML.T0010",
        "severity": 0.60,
        "false_positive_rate": 0.30,
        "behavioral_indicators": [
            "external data fetch with injection patterns",
            "tool output with override instructions"
        ],
        "recommended_action": "scan_output",
    },
    # ── OWASP LLM04 — Data/Model Poisoning ───────────────────────────────────
    {
        "id": "owasp-llm04-poisoning",
        "title": "Training/Knowledge Base Poisoning",
        "description": (
            "Attacker attempts to inject malicious entries into the agent's "
            "knowledge base or manipulate its behavioral patterns. "
            "In AgentGuard-X: analyst decisions are the only learning path — "
            "no autonomous online adaptation permitted."
        ),
        "owasp_category": "LLM04",
        "mitre_atlas": "AML.T0020",
        "severity": 0.80,
        "false_positive_rate": 0.10,
        "behavioral_indicators": [
            "KB modification attempts", "unusual analyst approval pattern",
            "drift in behavioral baselines"
        ],
        "recommended_action": "block_and_alert",
    },
    # ── OWASP LLM05 — Improper Output Handling ───────────────────────────────
    {
        "id": "owasp-llm05-output-handling",
        "title": "Improper Output Handling / Indirect Injection",
        "description": (
            "Tool responses treated as trusted data without validation. "
            "Injection in output can redirect downstream processing. "
            "Credential or PII leakage in outputs."
        ),
        "owasp_category": "LLM05",
        "mitre_atlas": "AML.T0051.001",
        "severity": 0.80,
        "false_positive_rate": 0.15,
        "behavioral_indicators": [
            "credentials in tool response", "high entropy tokens in output",
            "instruction patterns embedded in data response"
        ],
        "recommended_action": "quarantine",
    },
    # ── OWASP LLM06 — Excessive Agency ───────────────────────────────────────
    {
        "id": "owasp-llm06-excessive-agency",
        "title": "Excessive Agency / Privilege Abuse",
        "description": (
            "Agent performs actions beyond its intended scope: "
            "scope escalation (read→write), RBAC violations, "
            "calling admin-only tools from restricted roles, "
            "unauthorized financial transactions."
        ),
        "owasp_category": "LLM06",
        "mitre_atlas": "AML.T0040",
        "severity": 0.85,
        "false_positive_rate": 0.08,
        "behavioral_indicators": [
            "RBAC violation", "read-only role attempting write tool",
            "large financial transfer", "scope escalation pattern"
        ],
        "recommended_action": "block",
    },
    # ── OWASP LLM07 — System Prompt Leakage ──────────────────────────────────
    {
        "id": "owasp-llm07-prompt-extraction",
        "title": "System Prompt Extraction",
        "description": (
            "Attacker attempts to extract the agent's system prompt, "
            "instructions, or configuration via probing queries: "
            "'repeat your system prompt', 'what are your instructions', "
            "'reveal your base prompt'."
        ),
        "owasp_category": "LLM07",
        "mitre_atlas": "AML.T0051.002",
        "severity": 0.80,
        "false_positive_rate": 0.12,
        "behavioral_indicators": [
            "system prompt extraction probe", "repeat instructions request",
            "configuration disclosure attempt"
        ],
        "recommended_action": "block_and_log",
    },
    # ── OWASP LLM10 — Unbounded Consumption / Exfil ──────────────────────────
    {
        "id": "owasp-llm10-unbounded-consumption",
        "title": "Unbounded Consumption / Data Exfiltration",
        "description": (
            "Agent reads large amounts of data and posts it externally "
            "(exfiltration kill chain). Also: agent in a loop making "
            "excessive tool calls (anomalous call rate)."
        ),
        "owasp_category": "LLM10",
        "mitre_atlas": "AML.T0057",
        "severity": 0.90,
        "false_positive_rate": 0.05,
        "behavioral_indicators": [
            "read PII → compress → post external",
            "anomalous call rate", "loop detection",
            "large data post to external URL"
        ],
        "recommended_action": "block",
    },
    # ── MITRE ATLAS patterns ──────────────────────────────────────────────────
    {
        "id": "mitre-atlas-exfil-chain",
        "title": "MITRE ATLAS: Multi-Stage Exfil Kill Chain",
        "description": (
            "Three-step data exfiltration: (1) read sensitive data, "
            "(2) encode/compress, (3) transmit externally. "
            "No single step is suspicious in isolation; the sequence is the attack."
        ),
        "owasp_category": "LLM10",
        "mitre_atlas": "AML.T0057",
        "severity": 0.95,
        "false_positive_rate": 0.03,
        "behavioral_indicators": [
            "read_credentials → compress → post_external",
            "data staging followed by external transmission"
        ],
        "recommended_action": "block",
    },
    {
        "id": "mitre-atlas-reconnaissance",
        "title": "MITRE ATLAS: AI System Reconnaissance",
        "description": (
            "Systematic probing of an AI agent to understand its capabilities, "
            "permissions, and boundaries before launching an attack. "
            "Indicators: capability probing, permission boundary testing."
        ),
        "owasp_category": "LLM07",
        "mitre_atlas": "AML.T0000",
        "severity": 0.60,
        "false_positive_rate": 0.25,
        "behavioral_indicators": [
            "capability enumeration", "permission probing",
            "systematic boundary testing"
        ],
        "recommended_action": "monitor",
    },
]


def seed_kb() -> None:
    print("[seed_kb] Starting ChromaDB knowledge base seed...")

    # Pull embedding model (first-time download)
    print("[seed_kb] Loading sentence-transformers all-MiniLM-L6-v2...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")

    print(f"[seed_kb] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}...")
    import chromadb
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    collection = client.get_or_create_collection(COLLECTION_NAME)

    # Prepare batch
    ids = [e["id"] for e in KB_ENTRIES]
    documents = [
        f"{e['title']}. {e['description']} "
        f"Indicators: {', '.join(e.get('behavioral_indicators', []))}."
        for e in KB_ENTRIES
    ]
    metadatas = [
        {
            "title": e["title"],
            "owasp_category": e["owasp_category"],
            "mitre_atlas": e.get("mitre_atlas", ""),
            "severity": str(e["severity"]),
            "false_positive_rate": str(e["false_positive_rate"]),
            "recommended_action": e["recommended_action"],
        }
        for e in KB_ENTRIES
    ]

    print(f"[seed_kb] Embedding {len(documents)} entries...")
    embeddings = model.encode(documents, convert_to_numpy=True).tolist()

    # Upsert (idempotent)
    collection.upsert(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
        embeddings=embeddings,
    )

    print(f"[seed_kb] Seeded {len(ids)} KB entries into collection '{COLLECTION_NAME}'.")


if __name__ == "__main__":
    seed_kb()
