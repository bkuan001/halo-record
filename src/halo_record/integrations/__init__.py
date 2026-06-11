"""Framework adapters for halo-record.

Each adapter wires the recorder into a specific agent framework's tool-call
lifecycle so existing agents emit Halo Runtime Records without hand-written
instrumentation. Adapters import their framework lazily and are optional — the
core package has no third-party dependencies.

Every adapter records through one shared funnel (``_common.record_tool_call``)
and tags each record with its ``source`` — both which on-ramp saw the call and
its honest evidentiary tier (see ``record.SOURCES``):

  captured (boundary; strongest) — Halo saw the call as it happened:
    from halo_record.integrations.mcp import instrument_client_session
    from halo_record.integrations.langchain import HaloCallbackHandler
    from halo_record.integrations.openai_agents import HaloRunHooks

  ingested (built from telemetry the vendor already emits; weaker but near-zero
  friction — the witness attests "this is the stream you gave me"):
    from halo_record.integrations.otel import HaloSpanExporter, record_span
    from halo_record.integrations.litellm import HaloLiteLLMLogger, record_call
    from halo_record.integrations.langfuse import record_trace, record_observation
    from halo_record.integrations.gateway import record_log

The native ``Recorder`` is itself the strongest ``captured`` source. The shared,
framework-independent mapping helpers live in ``_common``.
"""

from ._common import classify_tool, record_tool_call

__all__ = ["classify_tool", "record_tool_call"]
