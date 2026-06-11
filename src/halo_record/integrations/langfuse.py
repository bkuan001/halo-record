"""Langfuse adapter — ingest, don't compete.

Langfuse is the most-adopted open-source LLM tracing store. If a team already
runs it, every agent run is already captured as a trace of nested observations
(spans/generations). This adapter reads those traces and turns each tool/LLM
observation into a Halo Runtime Record — no second instrumentation pass.

These records are the honest ``ingested`` tier: they are built from a trace the
vendor's own tooling produced and stored (and could in principle reshape before
Halo ever saw it), so the witness attests "this is the trace you exported", not
"I watched it happen" (see ``record.SOURCES``). Low-friction and real, just
weaker than a boundary interceptor — and the Runtime Report discloses that.

    # Pull traces via the Langfuse SDK and record each observation.
    from langfuse import Langfuse
    from halo_record import Recorder
    from halo_record.integrations.langfuse import record_trace
    for trace in Langfuse().api.trace.list().data:
        record_trace(Recorder("audit.jsonl"), trace)

    # Or map a single observation dict yourself (e.g. from the export API).
    from halo_record.integrations.langfuse import record_observation
    record_observation(recorder, obs)

Pure-stdlib: every function here accepts plain dicts (or SDK objects exposing the
same fields), so the adapter is testable without langfuse installed.
"""

from ._common import record_tool_call

_AGENT = {"id": "langfuse", "name": "langfuse-traces"}


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _is_tool_obs(obs):
    """Tool calls and generations are the observation types worth recording;
    plain spans/events that aren't model/tool calls are skipped as noise."""
    otype = str(_get(obs, "type", "") or "").upper()
    return otype in ("GENERATION", "TOOL", "SPAN") and bool(_get(obs, "name"))


def _tool_name(obs):
    name = _get(obs, "name") or "call"
    otype = str(_get(obs, "type", "") or "").upper()
    if otype == "GENERATION":
        model = _get(obs, "model") or name
        return "gen_ai:%s" % model
    if str(name).startswith("mcp__"):
        return name
    return name


def record_observation(recorder, obs, *, agent=None, session_id="local",
                       subject=None, summaries=True):
    """Map one Langfuse observation to a record, or None if it isn't a tool/LLM
    call. A ``level`` of ERROR (or a non-empty ``statusMessage`` on an error
    level) records the call as an error — never inferred otherwise."""
    if not _is_tool_obs(obs):
        return None
    level = str(_get(obs, "level", "") or "").upper()
    error = None
    if level == "ERROR":
        error = Exception(_get(obs, "statusMessage") or "observation level ERROR")
    tool_input = _get(obs, "input") or {"name": _get(obs, "name")}
    return record_tool_call(
        recorder, _tool_name(obs), tool_input, response=_get(obs, "output"),
        error=error, agent=agent or _AGENT, cls="connector",
        session_id=session_id, subject=subject, source="langfuse",
        summaries=summaries)


def record_trace(recorder, trace, *, agent=None, session_id=None, subject=None,
                 summaries=True):
    """Record every tool/LLM observation in a Langfuse trace. ``session_id``
    defaults to the trace's own id so a report groups a run together. Returns the
    list of records appended."""
    sid = session_id or _get(trace, "id") or "local"
    out = []
    for obs in (_get(trace, "observations") or []):
        rec = record_observation(recorder, obs, agent=agent, session_id=sid,
                                 subject=subject, summaries=summaries)
        if rec is not None:
            out.append(rec)
    return out
