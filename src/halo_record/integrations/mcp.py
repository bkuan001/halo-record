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

    session = await ClientSession(read, write).initialize()
    instrument_client_session(session, Recorder("audit.jsonl"), server="stripe")
    # every `await session.call_tool(name, args)` is now recorded

The MCP SDK is imported nowhere here — we wrap whatever ``call_tool`` coroutine
the session already has, so this adapter has no dependency of its own and works
across SDK versions. Recording is best-effort and never breaks the tool call.
"""

from ._common import record_tool_call

_AGENT = {"id": "mcp", "name": "mcp-client"}


def _result_payload(result):
    """Coerce an MCP ``CallToolResult`` (or anything) into a plain dict for the
    outcome — surfacing the SDK's ``isError`` so an error tool call is recorded
    as an error, not a success (ledger, not classifier)."""
    if result is None:
        return None
    is_error = getattr(result, "isError", None)
    content = getattr(result, "content", None)
    if is_error is None and content is None:
        return result  # already a plain value/dict; let derive_outcome handle it
    text_parts = []
    for item in (content or []):
        t = getattr(item, "text", None)
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
                              session_id="local", subject=None, summaries=True):
    """Wrap ``session.call_tool`` so every tool call is recorded. Returns the
    session (now instrumented). Idempotent: a session is only wrapped once.

    Works whether ``call_tool`` is async (the MCP SDK) or sync — the wrapper
    mirrors the original's awaitability so the agent's ``await`` still works."""
    import asyncio
    import functools

    original = getattr(session, "call_tool", None)
    if original is None or getattr(original, "_halo_wrapped", False):
        return session

    if asyncio.iscoroutinefunction(original):
        @functools.wraps(original)
        async def wrapper(name, arguments=None, *args, **kwargs):
            try:
                result = await original(name, arguments, *args, **kwargs)
            except Exception as exc:  # record the failure, then re-raise
                record_mcp_call(recorder, name, arguments, error=exc,
                                server=server, agent=agent, session_id=session_id,
                                subject=subject, summaries=summaries)
                raise
            record_mcp_call(recorder, name, arguments, response=result,
                            server=server, agent=agent, session_id=session_id,
                            subject=subject, summaries=summaries)
            return result
    else:
        @functools.wraps(original)
        def wrapper(name, arguments=None, *args, **kwargs):
            try:
                result = original(name, arguments, *args, **kwargs)
            except Exception as exc:
                record_mcp_call(recorder, name, arguments, error=exc,
                                server=server, agent=agent, session_id=session_id,
                                subject=subject, summaries=summaries)
                raise
            record_mcp_call(recorder, name, arguments, response=result,
                            server=server, agent=agent, session_id=session_id,
                            subject=subject, summaries=summaries)
            return result

    wrapper._halo_wrapped = True
    session.call_tool = wrapper
    return session
