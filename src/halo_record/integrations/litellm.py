"""LiteLLM gateway adapter — ingest, don't compete.

LiteLLM is the de-facto default LLM gateway/proxy: one OpenAI-compatible
endpoint in front of every provider. Teams already route their agent's calls
through it, so it already *sees* every request. This adapter consumes LiteLLM's
own success/failure callback stream and turns each call into a Halo Runtime
Record.

Because the evidence is built from telemetry LiteLLM already emits — not from a
boundary Halo controls — these records are the honest ``ingested`` tier: the
witness can attest "this is the stream you handed me", not "I watched it happen"
(see ``record.SOURCES``). Still useful and near-zero-friction; just weaker than a
native interceptor, and the report says so.

    # 1. Register as a LiteLLM callback — no app changes beyond config.
    import litellm
    from halo_record import Recorder
    from halo_record.integrations.litellm import HaloLiteLLMLogger
    litellm.callbacks = [HaloLiteLLMLogger(Recorder("audit.jsonl"))]

    # 2. Map a single logged call yourself (e.g. from a proxy log row).
    from halo_record.integrations.litellm import record_call
    record_call(recorder, kwargs, response_obj)

``record_call`` is pure-stdlib and testable without litellm installed; only the
``HaloLiteLLMLogger`` callback class needs the package, imported lazily.
"""

from ._common import record_tool_call

_AGENT = {"id": "litellm", "name": "litellm-gateway"}


def _model(kwargs):
    return (kwargs or {}).get("model") or (kwargs or {}).get("litellm_params", {}).get("model") or "llm"


def _input(kwargs):
    """Carry the request shape (model + message metadata) as the hashed input;
    raw prompt content is not required and is left to the redactor if present."""
    k = kwargs or {}
    msgs = k.get("messages") or []
    return {"model": _model(k), "messages": len(msgs) if isinstance(msgs, list) else msgs}


def record_call(recorder, kwargs, response_obj=None, *, error=None, agent=None,
                session_id="local", subject=None, summaries=True):
    """Map one LiteLLM call to a record. The tool name is ``gen_ai:<model>`` so
    it lands in the report next to every other LLM/tool call regardless of
    on-ramp. ``error`` (an exception/marker) records a failed call as an error —
    never inferred beyond an explicit failure (ledger, not classifier)."""
    return record_tool_call(
        recorder, "gen_ai:%s" % _model(kwargs), _input(kwargs),
        response=response_obj, error=error, agent=agent or _AGENT,
        cls="connector", session_id=session_id, subject=subject,
        source="litellm", summaries=summaries)


def _custom_logger_base():
    try:
        from litellm.integrations.custom_logger import CustomLogger
    except ImportError as exc:  # pragma: no cover - litellm not installed
        raise ImportError(
            "HaloLiteLLMLogger requires litellm. "
            "Install with: pip install litellm"
        ) from exc
    return CustomLogger


def _build_logger_class():
    CustomLogger = _custom_logger_base()

    class _HaloLiteLLMLogger(CustomLogger):
        """Records each LiteLLM call from its success/failure callbacks."""

        def __init__(self, recorder, *, session_id="local", agent=None,
                     subject=None, summaries=True):
            self.recorder = recorder
            self.session_id = session_id
            self.agent = agent
            self.subject = subject
            self.summaries = summaries

        def log_success_event(self, kwargs, response_obj, start_time, end_time):
            record_call(self.recorder, kwargs, response_obj, agent=self.agent,
                        session_id=self.session_id, subject=self.subject,
                        summaries=self.summaries)

        def log_failure_event(self, kwargs, response_obj, start_time, end_time):
            err = (kwargs or {}).get("exception") or Exception("litellm call failed")
            record_call(self.recorder, kwargs, response_obj, error=err,
                        agent=self.agent, session_id=self.session_id,
                        subject=self.subject, summaries=self.summaries)

        # Async proxies emit the *_async variants; mirror them.
        async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
            self.log_success_event(kwargs, response_obj, start_time, end_time)

        async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
            self.log_failure_event(kwargs, response_obj, start_time, end_time)

    return _HaloLiteLLMLogger


def __getattr__(name):
    if name == "HaloLiteLLMLogger":
        return _build_logger_class()
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
