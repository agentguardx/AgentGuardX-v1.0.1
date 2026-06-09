"""OpenTelemetry setup — instruments every triage stage and gateway hook.

CRITICAL: Observability is NEVER turned off, even when the PoC toggle is OFF.
When enforcement is disabled, attacks succeed — but they are FULLY VISIBLE
in Prometheus + Grafana + Loki. That contrast is the entire before/after demo.

All spans include:
  - enforcement_active: true/false (toggle state)
  - verdict: allow/grey_band/block
  - r_score: composite risk score
  - owasp_category: which OWASP LLM category triggered
  - agent_id, agent_role, tool_name
"""

from __future__ import annotations

import os
from typing import Optional

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "agentguard-x")

_tracer: Optional[trace.Tracer] = None
_meter: Optional[metrics.Meter] = None


def setup_telemetry(service_name: str = _SERVICE_NAME) -> None:
    global _tracer, _meter

    resource = Resource.create({"service.name": service_name})

    # ── Tracing ───────────────────────────────────────────────────────────────
    tracer_provider = TracerProvider(resource=resource)
    try:
        span_exporter = OTLPSpanExporter(endpoint=_OTEL_ENDPOINT, insecure=True)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    except Exception:
        pass  # OTel collector not available — traces go nowhere; app still runs
    trace.set_tracer_provider(tracer_provider)
    _tracer = trace.get_tracer(service_name)

    # ── Metrics ───────────────────────────────────────────────────────────────
    try:
        metric_exporter = OTLPMetricExporter(endpoint=_OTEL_ENDPOINT, insecure=True)
        reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=15000)
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    except Exception:
        meter_provider = MeterProvider(resource=resource)
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter(service_name)

    # ── Define key metrics ────────────────────────────────────────────────────
    _meter.create_counter(
        "agentguard.requests.total",
        description="Total triage requests",
    )
    _meter.create_counter(
        "agentguard.blocks.total",
        description="Total blocked requests (by verdict type)",
    )
    _meter.create_histogram(
        "agentguard.triage.latency_ms",
        description="End-to-end triage latency in milliseconds",
        unit="ms",
    )
    _meter.create_histogram(
        "agentguard.risk_score",
        description="Distribution of composite R scores",
    )
    _meter.create_up_down_counter(
        "agentguard.hold_queue.size",
        description="Number of operations currently in analyst hold queue",
    )


def get_tracer() -> trace.Tracer:
    if _tracer is None:
        return trace.get_tracer(_SERVICE_NAME)
    return _tracer


def get_meter() -> metrics.Meter:
    if _meter is None:
        return metrics.get_meter(_SERVICE_NAME)
    return _meter
