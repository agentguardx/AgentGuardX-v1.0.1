"""Exfil capture server — local HTTP listener that captures POST requests.

This is the ONE controlled real external element in FinanceFlow.
post_external tool sends to this server; nothing leaves localhost.
"""
