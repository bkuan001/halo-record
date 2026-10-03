"""MCP (Model Context Protocol) adapter — framework-agnostic capture.

The highest-leverage on-ramp: instead of one adapter per agent framework, wrap
the MCP ``ClientSession`` an agent uses to call tools, and *any* MCP-using agent
— LangChain, OpenAI Agents, a bespoke loop — emits Halo Runtime Records for
every tool call, regardless of which framework drives it. MCP tool calls map
cleanly onto the schema: each is a ``connector`` action with scope
``mcp:<server>``, exactly as the Claude Code hook already classifies ``mcp__``
tools.

    from halo_record import Recorder
    from halo_record.integrations.mcp import instrument_client_session

    async with Client(server) as client:          # mcp 2.x (``from mcp import Client``)
        instrument_client_session(client, Recorder("audit.jsonl"), server="stripe")
        # every `await client.call_tool(name, args)` is now recorded

On mcp 1.x, wrap the initialized ``ClientSession`` the same way.

The MCP SDK is imported nowhere here — we wrap whatever ``call_tool`` coroutine
the session already has, so this adapter has no dependency of its own and works
across SDK versions. Recording is best-effort and never breaks the tool call.
"""

from ..session import recording_failed
from ._common import record_tool_call

_AGENT = {"id": "mcp", "name": "mcp-client"}


def _field(obj, *names):
    """First non-None value among ``names``, read as a key on a dict or as an
    attribute on anything else."""
    for name in names:
        value = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _result_payload(result):
    """Coerce an MCP ``CallToolResult`` (or anything) into a plain dict for the
    outcome — surfacing the SDK's error flag so an error tool call is recorded
    as an error, not a success (ledger, not classifier). The flag is
    ``isError`` before mcp 2 and ``is_error`` from mcp 2 on; both are read,
    on result objects and on plain dict results alike."""
    if result is None:
        return None
    is_error = _field(result, "isError", "is_error")
    content = _field(result, "content")
    if is_error is None and (content is None or isinstance(result, dict)):
        return result  # already a plain value/dict; let derive_outcome handle it
    if isinstance(result, dict) and not isinstance(content, list):
        payload = dict(result)
        payload.pop("isError", None)
        payload["is_error"] = bool(is_error)
        return payload
    text_parts = []
    for item in (content or []):
        t = _field(item, "text")
        if t is not None:
            text_parts.append(t)
    payload = {"is_error": bool(is_error)}
    if text_parts:
        payload["summary"] = " ".join(text_parts)
    return payload


def record_mcp_call(recorder, name, arguments, *, response=None, error=None,
                    server="mcp", agent=None, session_id="local", subject=None,
                    summaries=True):
    """Record one MCP tool call. Tool name is normalized to ``mcp__<server>__<name>``
    so it classifies as a connector with scope ``mcp:<server>`` — the same shape
    the Claude Code hook produces, so reports look identical across on-ramps."""
    tool = name if str(name).startswith("mcp__") else "mcp__%s__%s" % (server, name)
    return record_tool_call(
        recorder, tool, arguments, response=_result_payload(response),
        error=error, agent=agent or _AGENT, cls="connector",
        session_id=session_id, subject=subject, source="mcp",
        summaries=summaries)


def instrument_client_session(session, recorder, *, server="mcp", agent=None,
                              session_id="local", subject=None, summaries=True,
                              strict_recording=None):
    """Wrap ``session.call_tool`` so every tool call is recorded. Returns the
    session (now instrumented). Idempotent: a session is only wrapped once.

    Works whether ``call_tool`` is async (the MCP SDK) or sync — the wrapper
    mirrors the original's awaitability so the agent's ``await`` still works.
    A recording failure is reported on stderr and the call's result or error
    passes through unchanged; ``strict_recording=True`` (or
    ``HALO_STRICT_RECORDING=1``) raises it instead."""
    import asyncio
    import functools

    original = getattr(session, "call_tool", None)
    if original is None or getattr(original, "_halo_wrapped", False):
        return session

    def record(**kw):
        # The tool has already run (or already failed). A recording failure is
        # reported, never raised: raising here would turn a completed call into
        # an exception, and a retry would repeat the tool's side effects.
        try:
            record_mcp_call(recorder, server=server, agent=agent,
                            session_id=session_id, subject=subject,
                            summaries=summaries, **kw)
        except Exception as exc:
            recording_failed(kw.get("name"), exc, strict_recording)

    if asyncio.iscoroutinefunction(original):
        @functools.wraps(original)
        async def wrapper(name, arguments=None, *args, **kwargs):
            try:
                result = await original(name, arguments, *args, **kwargs)
            except Exception as exc:  # record the failure, then re-raise
                record(name=name, arguments=arguments, error=exc)
                raise
            record(name=name, arguments=arguments, response=result)
            return result
    else:
        @functools.wraps(original)
        def wrapper(name, arguments=None, *args, **kwargs):
            try:
                result = original(name, arguments, *args, **kwargs)
            except Exception as exc:
                record(name=name, arguments=arguments, error=exc)
                raise
            record(name=name, arguments=arguments, response=result)
            return result

    wrapper._halo_wrapped = True
    session.call_tool = wrapper
    return session
