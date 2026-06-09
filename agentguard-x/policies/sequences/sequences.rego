package agentguard.sequences

import future.keywords.if
import future.keywords.in

# ── Kill-chain sequence detection ─────────────────────────────────────────────
# Detects dangerous call sequences within a session.
# These are SOFT SIGNALS (score contributors) not hard gates.
# Hard gates live in Stage 1; sequences feed Stage 3 soft scoring.

# Known kill chains: [early tools ...] → final dangerous tool
kill_chains := [
    ["read_customer_pii_tool", "compress_data_tool", "post_external_tool"],
    ["get_account_tool", "read_customer_pii_tool", "post_external_tool"],
    ["run_report_tool", "compress_data_tool", "post_external_tool"],
]

# Blocked sequences: certain tool orders are always violations
blocked_sequences := [
    ["execute_code_tool", "post_external_tool"],   # code then exfil
]

# ── Decision ──────────────────────────────────────────────────────────────────
default kill_chain_detected := false

kill_chain_detected if {
    some chain in kill_chains
    sequence_present(input.session_tools, chain)
}

default blocked_sequence := false

blocked_sequence if {
    some seq in blocked_sequences
    sequence_present(input.session_tools, seq)
}

# Risk score contribution from sequences
sequence_risk_score := 0.90 if { kill_chain_detected } else :=
                       0.80 if { blocked_sequence } else := 0.0

# ── Helpers ───────────────────────────────────────────────────────────────────
# Check if needle_seq appears as subsequence in haystack
sequence_present(haystack, needle_seq) if {
    count(needle_seq) > 0
    _subsequence_idx(haystack, needle_seq, 0, 0)
}

_subsequence_idx(haystack, needle, hi, ni) if {
    ni >= count(needle)
}

_subsequence_idx(haystack, needle, hi, ni) if {
    hi < count(haystack)
    haystack[hi] == needle[ni]
    _subsequence_idx(haystack, needle, hi + 1, ni + 1)
}

_subsequence_idx(haystack, needle, hi, ni) if {
    hi < count(haystack)
    haystack[hi] != needle[ni]
    _subsequence_idx(haystack, needle, hi + 1, ni)
}
