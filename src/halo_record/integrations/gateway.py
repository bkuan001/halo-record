"""Generic LLM gateway / proxy-log adapter — ingest, don't compete.

Not every team runs LiteLLM or Langfuse, but almost every team's agent traffic
already passes through *some* gateway or reverse proxy that writes an access log
(Cloudflare AI Gateway, Portkey, an nginx/Envoy in front of the model, an API
gateway). This adapter maps a plain log row — whatever fields you can supply —
into a Halo Runtime Record, so even a team with nothing but proxy logs has an
on-ramp.

These are the honest ``ingested`` tier and, being a generic log, often the
weakest of all: the row is whatever the proxy chose to write, after the fact, so
the witness attests "this is the log you gave me" (see ``record.SOURCES``). It is
still real, anchorable evidence — and the Runtime Report is explicit that it was
ingested, not boundary-captured.

    from halo_record import Recorder
    from halo_record.integrations.gateway import record_log

    # A log row from your proxy — pass whatever you have.
    record_log(Recorder("audit.jsonl"), {
        "tool": "gen_ai:gpt-4o", "model": "gpt-4o",
        "method": "POST", "path": "/v1/chat/completions",
        "status": 200, "subject": "acme-corp",
    })

Pure-stdlib; accepts a plain dict so it is testable with no dependencies.
"""

from ._common import record_tool_call


def _norm_agent(agent, row):
    if agent is not None:
        return agent
    name = row.get("gateway") or row.get("proxy") or "gateway"
    return {"id": "gateway", "name": str(name)}


def _tool_name(row):
    """Prefer an explicit tool/model; otherwise synthesize from the HTTP route so
    every row still classifies and lands in the report."""
    if row.get("tool"):
        return row["tool"]
    if row.get("model"):
        return "gen_ai:%s" % row["model"]
    path = row.get("path") or row.get("url") or "request"
    return "http:%s" % path


def _error(row):
    """An HTTP status >= 400 (or an explicit error field) records the call as an
    error — never inferred beyond what the row states."""
    if row.get("error"):
        return row["error"] if isinstance(row["error"], Exception) else Exception(str(row["error"]))
    status = row.get("status") or row.get("status_code")
    try:
        if status is not None and int(status) >= 400:
            return Exception("gateway status %s" % status)
    except (TypeError, ValueError):
        pass
    return None


def record_log(recorder, row, *, agent=None, session_id=None, subject=None,
               summaries=True):
    """Map one gateway/proxy log row (a dict) to a record. ``subject`` may be
    given directly or carried on the row as ``row['subject']``; the input is the
    request metadata (method/path/model), hashed and redacted like any input."""
    row = dict(row or {})
    subj = subject if subject is not None else row.get("subject")
    sid = session_id or row.get("session_id") or row.get("request_id") or "local"
    tool_input = {k: row[k] for k in ("method", "path", "url", "model", "status")
                  if k in row} or {"request": _tool_name(row)}
    return record_tool_call(
        recorder, _tool_name(row), tool_input, error=_error(row),
        agent=_norm_agent(agent, row), session_id=sid, subject=subj,
        source="gateway", summaries=summaries)
