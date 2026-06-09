"""FinanceFlow tools package — simulated tools with reversibility + OWASP metadata."""

from .registry import TOOL_REGISTRY, ToolMetadata
from .account_tools import get_account_tool
from .transaction_tools import query_transactions_tool
from .pii_tools import read_customer_pii_tool
from .financial_tools import transfer_funds_tool, run_report_tool
from .market_tools import fetch_market_data_tool
from .communication_tools import send_email_tool
from .compute_tools import compress_data_tool, post_external_tool
from .code_tools import execute_code_tool

ALL_TOOLS = [
    get_account_tool,
    query_transactions_tool,
    read_customer_pii_tool,
    transfer_funds_tool,
    run_report_tool,
    fetch_market_data_tool,
    send_email_tool,
    compress_data_tool,
    post_external_tool,
    execute_code_tool,
]

RESEARCH_TOOLS = [
    get_account_tool,
    run_report_tool,
    fetch_market_data_tool,
]

DATA_TOOLS = [
    get_account_tool,
    query_transactions_tool,
    run_report_tool,
    fetch_market_data_tool,
    read_customer_pii_tool,
]

ADMIN_TOOLS = ALL_TOOLS

ROLE_TOOLS = {
    "research": RESEARCH_TOOLS,
    "data": DATA_TOOLS,
    "admin": ADMIN_TOOLS,
}

__all__ = [
    "TOOL_REGISTRY",
    "ToolMetadata",
    "ALL_TOOLS",
    "RESEARCH_TOOLS",
    "DATA_TOOLS",
    "ADMIN_TOOLS",
    "ROLE_TOOLS",
]
