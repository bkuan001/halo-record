"""OpenTelemetry GenAI adapter — ingest, don't compete.

Many teams already emit OpenTelemetry GenAI spans (the ``gen_ai.*`` semantic
conventions). This adapter *consumes* those spans and turns each tool/LLM call
into a Halo Runtime Record. Halo is the independent evidence/attestation layer
that sits on top of telemetry the team already produces — it does not try to own
or replace the tracing standard. (OTel is a feed-into, not a substitute: a vendor
keeps their existing observability; Halo adds the tamper-evident, witnessed
record a buyer's security team can trust.)

Two ways in:

    # 1. Register an exporter alongside your existing ones — no app changes.
    from opentelemetry.sdk.trace import TracerProvider
    from halo_record import Recorder
    from halo_record.integrations.otel import HaloSpanExporter
    provider.add_span_processor(SimpleSpanProcessor(HaloSpanExporter(Recorder("audit.jsonl"))))

    # 2. Map a single span dict yourself (e.g. from a collector pipeline).
    from halo_record.integrations.otel import record_span
    record_span(recorder, {"name": "...", "attributes": {...}})

``record_span`` is pure-stdlib and testable without OpenTelemetry installed; only
``HaloSpanExporter`` needs the SDK, imported lazily.
"""

from ._common import record_tool_call

_AGENT = {"id": "otel", "name": "otel-genai"}

# GenAI semantic-convention attribute keys we read.
_TOOL_NAME = "gen_ai.tool.name"
_OP_NAME = "gen_ai.operation.name"
_SYSTEM = "gen_ai.system"


def _attrs(span):
    """Attributes as a plain dict, whether ``span`` is a dict or an OTel span."""
    a = span.get("attributes") if isinstance(span, dict) else getattr(span, "attributes", None)
    return dict(a) if a else {}


def _span_name(span):
    if isinstance(span, dict):
        return span.get("name") or ""
    return getattr(span, "name", "") or ""


def _is_error(span):
    """True when the span's status is ERROR (so a failed call is recorded as
    an error — never inferred beyond the explicit status)."""
    status = span.get("status") if isinstance(span, dict) else getattr(span, "status", None)
    if status is None:
        return False
    code = status.get("status_code") if isinstance(status, dict) else getattr(status, "status_code", None)
    return str(code).upper().endswith("ERROR")


def is_genai_span(span):
    """Only ingest spans that are actually GenAI tool/LLM calls — skip the rest
    of an app's trace so the record is agent runtime evidence, not noise."""
    attrs = _attrs(span)
    return bool(attrs.get(_TOOL_NAME) or attrs.get(_OP_NAME) or attrs.get(_SYSTEM))


def record_span(recorder, span, *, agent=None, session_id="local", subject=None,
                summaries=True):
    """Map one GenAI span to a record. Returns the record, or None if the span
    isn't a GenAI call. The tool name prefers ``gen_ai.tool.name``; an LLM call
    with only an operation name is recorded under ``gen_ai:<operation>``."""
    if not is_genai_span(span):
        return None
    attrs = _attrs(span)
    system = attrs.get(_SYSTEM) or "otel"
    tool = attrs.get(_TOOL_NAME)
    if tool:
        tool_name = "mcp__%s__%s" % (system, tool)
        cls = "connector"
    else:
        tool_name = "gen_ai:%s" % (attrs.get(_OP_NAME) or "call")
        cls = "connector"
    # Carry the GenAI attributes as the input (hashed + redacted summary); raw
    # prompt/response content is never required and stays out unless the span
    # itself put it in attributes.
    tool_input = {k: v for k, v in attrs.items() if str(k).startswith("gen_ai.")}
    return record_tool_call(
        recorder, tool_name, tool_input or {"span": _span_name(span)},
        error=Exception("span status ERROR") if _is_error(span) else None,
        agent=agent or _AGENT, cls=cls, session_id=session_id, subject=subject,
        source="otel", summaries=summaries)


def _span_exporter_base():
    try:
        from opentelemetry.sdk.trace.export import SpanExporter
    except ImportError as exc:  # pragma: no cover - SDK not installed
        raise ImportError(
            "HaloSpanExporter requires opentelemetry-sdk. "
            "Install with: pip install opentelemetry-sdk"
        ) from exc
    return SpanExporter


def _build_exporter_class():
    SpanExporter = _span_exporter_base()

    class _HaloSpanExporter(SpanExporter):
        """A drop-in OTel exporter that records GenAI spans as Halo records.
        Non-GenAI spans pass through untouched (nothing is recorded)."""

        def __init__(self, recorder, *, agent=None, session_id="local",
                     subject=None, summaries=True):
            self.recorder = recorder
            self.agent = agent
            self.session_id = session_id
            self.subject = subject
            self.summaries = summaries

        def export(self, spans):
            from opentelemetry.sdk.trace.export import SpanExportResult
            for span in spans:
                try:
                    record_span(self.recorder, span, agent=self.agent,
                                session_id=self.session_id, subject=self.subject,
                                summaries=self.summaries)
                except Exception:
                    pass  # never break the trace pipeline
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

    return _HaloSpanExporter


def __getattr__(name):
    if name == "HaloSpanExporter":
        return _build_exporter_class()
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
