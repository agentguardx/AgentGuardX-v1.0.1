"""OpenTelemetry instrumentation — wraps everything, never off (§15)."""

from .telemetry import setup_telemetry, get_tracer, get_meter

__all__ = ["setup_telemetry", "get_tracer", "get_meter"]
