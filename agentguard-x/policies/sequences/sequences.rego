package agentguard.sequences

import future.keywords.if
import future.keywords.in

# ── Kill-chain sequence detection ─────────────────────────────────────────────
# Detects dangerous call sequences within a session.
# These are SOFT SIGNALS (score contributors) not hard gates.
# Hard gates live in Stage 1; sequences feed Stage 3 soft scoring.

kill_chains := [
    ["read_customer_pii_tool", "compress_data_tool", "post_external_tool"],
    ["get_account_tool", "read_customer_pii_tool", "post_external_tool"],
    ["run_report_tool", "compress_data_tool", "post_external_tool"],
]

blocked_sequences := [
    ["execute_code_tool", "post_external_tool"],
]

# ── Decisions ─────────────────────────────────────────────────────────────────
default kill_chain_detected := false

kill_chain_detected if {
    some chain in kill_chains
    _subseq3(input.session_tools, chain[0], chain[1], chain[2])
}

default blocked_sequence := false

blocked_sequence if {
    some seq in blocked_sequences
    _subseq2(input.session_tools, seq[0], seq[1])
}

sequence_risk_score := 0.90 if { kill_chain_detected }
else := 0.80 if { blocked_sequence }
else := 0.0

# ── Non-recursive subsequence helpers ─────────────────────────────────────────
# OPA forbids recursion (Datalog guarantee of termination).
# Existential index search over the session_tools array achieves the same
# result: find indices i < j (< k) where elements match the pattern in order.

_subseq2(haystack, a, b) if {
    some i, j
    haystack[i] == a
    haystack[j] == b
    i < j
}

_subseq3(haystack, a, b, c) if {
    some i, j, k
    haystack[i] == a
    haystack[j] == b
    haystack[k] == c
    i < j
    j < k
}
