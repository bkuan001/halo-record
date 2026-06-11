"""Shared, framework-independent core for the adapters.

Every framework adapter ultimately does the same thing: take a tool name, its
input, and an outcome (return value or error), and append one Halo Runtime
Record. This module is that single funnel, so classification, scope derivation,
redaction, hashing, and per-tenant routing behave identically regardless of
which ecosystem the event came from. Pure-stdlib — no framework imports here.
"""

from ..capture import derive_outcome
from ..hook import ACTION_TYPE_BY_CLASS, CATEGORY_BY_CLASS, derive_scope
from ..record import build


def classify_tool(tool_name):
    """Map an arbitrary tool name to a Halo action class. Unlike the Claude Code
    hook's classifier, this never returns None (adapters decide what to skip) —
    an unrecognized tool is a generic ``connector`` call, the safe default for a
    trust-boundary action whose nature we can't infer from the name alone."""
    if not tool_name:
        return "connector"
    if tool_name.startswith("mcp__") or tool_name.startswith("mcp:"):
        return "connector"
    lowered = tool_name.lower()
    if lowered in ("bash", "shell", "exec", "python", "code_interpreter"):
        return "exec"
    if lowered in ("write", "edit", "write_file", "create_file", "put"):
        return "data_write"
    if lowered in ("read", "glob", "grep", "ls", "read_file", "list", "get"):
        return "data_read"
    if lowered in ("webfetch", "websearch", "fetch", "search", "http", "browse"):
        return "network"
    return "connector"


def record_tool_call(recorder, tool_name, tool_input=None, *, response=None,
                     error=None, agent=None, cls=None, action_type=None,
                     category=None, scope=None, session_id="local",
                     decision="allowed", approver=None, subject=None,
                     source=None, summaries=True):
    """Build and append one record for a completed tool call. ``response`` and
    ``error`` are mutually exclusive (error wins); the outcome is derived the
    same way the SDK and the hook derive it — never inferred beyond an explicit
    error marker (ledger, not classifier). ``source`` tags where the call was
    observed (which adapter, and whether boundary-captured or ingested from the
    vendor's own telemetry). Returns the appended record."""
    cls = cls or classify_tool(tool_name)
    record = build(
        action_type or ACTION_TYPE_BY_CLASS.get(cls, "tool_call"),
        category or CATEGORY_BY_CLASS.get(cls, "security"),
        tool=tool_name,
        tool_input=tool_input,
        session_id=session_id,
        agent=agent,
        scope=scope or derive_scope(cls, tool_name),
        decision=decision,
        approver=approver,
        outcome=derive_outcome(response, error=error),
        subject=subject,
        source=source,
        summaries=summaries,
    )
    recorder.append(record)
    return record


def record_model_call(recorder, *, provider, model, zdr=None, purpose=None,
                      messages=None, response=None, error=None, agent=None,
                      session_id="local", subject=None, source=None,
                      summaries=True):
    """Record one LLM generation as a first-class action.

    The buyer's first question about a bought agent is "which model saw my
    data, and was it allowed to keep it?" — so model calls get their own loud
    entry: ``tool=model.generate``, ``scope=model:<provider>``, category
    ``privacy``, with provider / model / zero-data-retention / purpose in the
    (hashed + summarized) input. Raw prompts and completions never enter the
    record — same rule as every other action."""
    tool_input = {"provider": provider, "model": model}
    if zdr is not None:
        tool_input["zdr"] = bool(zdr)
    if purpose:
        tool_input["purpose"] = purpose
    if messages is not None:
        tool_input["messages"] = messages
    return record_tool_call(
        recorder, "model.generate", tool_input,
        response=response, error=error, agent=agent,
        action_type="tool_call", category="privacy",
        scope="model:%s" % provider, session_id=session_id,
        subject=subject, source=source, summaries=summaries)
