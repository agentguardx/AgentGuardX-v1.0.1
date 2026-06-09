package agentguard.rbac

import future.keywords.if
import future.keywords.in

# ── Role definitions ──────────────────────────────────────────────────────────
# Tools allowed per role. Under-declared = fail closed.
role_tools := {
    "research": {
        "get_account_tool",
        "run_report_tool",
        "fetch_market_data_tool",
    },
    "data": {
        "get_account_tool",
        "query_transactions_tool",
        "run_report_tool",
        "fetch_market_data_tool",
        "read_customer_pii_tool",
    },
    "admin": {
        "get_account_tool",
        "query_transactions_tool",
        "read_customer_pii_tool",
        "transfer_funds_tool",
        "run_report_tool",
        "fetch_market_data_tool",
        "send_email_tool",
        "compress_data_tool",
        "post_external_tool",
        "execute_code_tool",
    },
}

# Rate limits: max calls per 60-second window per role
role_rate_limits := {
    "research": 50,
    "data": 30,
    "admin": 20,  # admin tools are high-impact; tighter rate
}

# Risk scores for specific tool calls (used in composite score)
tool_risk_scores := {
    "transfer_funds_tool": 0.75,
    "execute_code_tool": 0.75,
    "post_external_tool": 0.80,
    "read_customer_pii_tool": 0.40,
    "send_email_tool": 0.50,
    "compress_data_tool": 0.20,
}

# ── Decision ──────────────────────────────────────────────────────────────────
default allow := false

allow if {
    tool_allowed_for_role
    not rate_limit_exceeded
}

# Tool must be in role's declared envelope
tool_allowed_for_role if {
    input.tool_name in role_tools[input.agent_role]
}

# Rate limit: enforced via Redis in Stage 5; OPA tracks policy limit
rate_limit_exceeded if {
    count(input.recent_calls) > role_rate_limits[input.agent_role]
}

# ── Violations list ───────────────────────────────────────────────────────────
violations[msg] if {
    not tool_allowed_for_role
    msg := sprintf(
        "RBAC: role '%v' cannot call '%v' (allowed: %v)",
        [input.agent_role, input.tool_name, role_tools[input.agent_role]]
    )
}

violations[msg] if {
    rate_limit_exceeded
    msg := sprintf(
        "Rate limit: role '%v' exceeded %v calls/60s",
        [input.agent_role, role_rate_limits[input.agent_role]]
    )
}

# ── Risk score ────────────────────────────────────────────────────────────────
risk_score := score if {
    score := tool_risk_scores[input.tool_name]
} else := 0.0
