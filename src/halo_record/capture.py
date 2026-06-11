"""Ergonomic capture for agent tool calls.

Wrap a tool call so a conformant, hash-chained record is appended automatically,
with the outcome derived from the return value or a raised exception. These are
framework-agnostic — the decorator and context manager work for any Python
agent. Framework-specific adapters live in ``halo_record.integrations``.

    from halo_record import Recorder, record

    rec = Recorder("audit.jsonl")

    @record(rec, category="security", scope="db.read")
    def search_customers(query):
        return db.run(query)

Every call to ``search_customers`` now appends a record: the bound arguments
become the input (hashed + redacted summary, never raw), the return value or
exception becomes the outcome.
"""

import functools
import inspect

from .canon import input_hash
from .record import build
from .redact import redact_text
from .session import current_recorder


def _extract_text(obj, depth=0):
    if depth > 6:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return " ".join(_extract_text(i, depth + 1) for i in obj)
    if isinstance(obj, dict):
        return " ".join(_extract_text(v, depth + 1) for v in obj.values())
    return str(obj)


def derive_outcome(response, error=None):
    """Deterministic outcome block: what the call actually did.

    ``status`` is ``error`` only on a raised exception or an explicit error
    marker in the response — never inferred (ledger, not classifier). The full
    response is hashed into the chain; only a redacted summary is stored, never
    the raw content.
    """
    if error is not None:
        return {
            "status": "error",
            "summary": redact_text(str(error))[:200],
            "hash": input_hash({"error": str(error)}),
        }
    status = "ok"
    if isinstance(response, dict) and (
        response.get("is_error")
        or response.get("error")
        or response.get("status") == "error"
    ):
        status = "error"
    out = {"status": status, "hash": input_hash(response)}
    summary = redact_text(_extract_text(response))[:200]
    if summary:
        out["summary"] = summary
    return out


class record_call:
    """Context manager that records exactly one tool call.

        with record_call(rec, "search", {"q": "x"}, category="security",
                         scope="db.read") as call:
            call.result = do_search("x")

    On exit it appends a record whose outcome reflects ``call.result``. If the
    block raises, an error outcome is recorded and the exception propagates
    (the call is never silently swallowed). ``recorder`` may be ``None``, in
    which case the recorder bound by an enclosing ``trace`` is used; if none is
    bound, a ``RuntimeError`` is raised at exit rather than dropping the record.
    """

    def __init__(self, recorder=None, tool=None, tool_input=None, *, category="security",
                 action_type="tool_call", scope=None, session_id="local",
                 agent=None, decision="allowed", approver=None,
                 subject=None, summaries=True):
        self.recorder = recorder
        self.tool = tool
        self.tool_input = tool_input
        self.category = category
        self.action_type = action_type
        self.scope = scope
        self.session_id = session_id
        self.agent = agent
        self.decision = decision
        self.approver = approver
        self.subject = subject
        self.summaries = summaries
        self.result = None
        self.record = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        recorder = self.recorder or current_recorder()
        if recorder is None:
            raise RuntimeError(
                "no recorder: pass one to record_call(...) or wrap the agent "
                "with halo_record.trace(...) to bind an active recorder")
        outcome = derive_outcome(self.result, error=exc)
        self.record = build(
            self.action_type, self.category, tool=self.tool,
            tool_input=self.tool_input, session_id=self.session_id,
            agent=self.agent, scope=self.scope, decision=self.decision,
            approver=self.approver, outcome=outcome,
            subject=self.subject, summaries=self.summaries,
        )
        recorder.append(self.record)
        return False  # never suppress the exception


def record(recorder=None, *, category="security", action_type="tool_call",
           scope=None, tool=None, session_id="local", agent=None,
           decision="allowed", approver=None, subject=None, summaries=True):
    """Decorator that records every call to a tool function.

    The function's bound arguments become the input; its return value (or a
    raised exception) becomes the outcome. ``tool`` defaults to the function
    name. ``subject`` tags the record with its tenant/customer (see ``build``);
    ``summaries=False`` records hashes only, no payload text. ``recorder`` may
    be omitted to record onto whatever recorder an enclosing ``trace`` has
    bound — letting a tool be decorated once and reused across agents/tenants.
    """

    def decorator(fn):
        name = tool or getattr(fn, "__name__", "tool")
        try:
            sig = inspect.signature(fn)
        except (ValueError, TypeError):
            sig = None

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if sig is not None:
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    tool_input = dict(bound.arguments)
                except TypeError:
                    tool_input = {"args": list(args), "kwargs": kwargs}
            else:
                tool_input = {"args": list(args), "kwargs": kwargs}
            with record_call(
                recorder, name, tool_input, category=category,
                action_type=action_type, scope=scope, session_id=session_id,
                agent=agent, decision=decision, approver=approver,
                subject=subject, summaries=summaries,
            ) as call:
                call.result = fn(*args, **kwargs)
                return call.result

        return wrapper

    return decorator
