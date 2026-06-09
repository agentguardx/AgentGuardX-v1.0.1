package agentguard.rbac.decision

import data.agentguard.rbac
import data.agentguard.sequences
import future.keywords.if

# Combined RBAC + sequence decision (queried by Stage 3)
allow := rbac.allow

violations := rbac.violations

# Composite risk score: max of RBAC tool risk and sequence risk
risk_score := max_score if {
    scores := [rbac.risk_score, sequences.sequence_risk_score]
    max_score := max(scores)
} else := rbac.risk_score
