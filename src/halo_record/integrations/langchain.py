"""LangChain adapter.

Attach ``HaloCallbackHandler`` to any LangChain/LangGraph agent and every tool
the agent invokes is recorded as a Halo Runtime Record — no per-tool
instrumentation:

    from halo_record import Recorder
    from halo_record.integrations.langchain import HaloCallbackHandler

    rec = Recorder("audit.jsonl")
    agent.invoke(inputs, config={"callbacks": [HaloCallbackHandler(rec)]})

The handler subclasses LangChain's ``BaseCallbackHandler``. LangChain is
imported lazily so it is only required when this adapter is actually used.
"""

from ._common import record_tool_call

_AGENT = {"id": "langchain", "name": "langchain"}


def _base_callback_handler():
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError:  # pragma: no cover - older layout
        try:
            from langchain.callbacks.base import BaseCallbackHandler
        except ImportError as exc:
            raise ImportError(
                "HaloCallbackHandler requires langchain-core. "
                "Install with: pip install langchain-core"
            ) from exc
    return BaseCallbackHandler


def _build_handler_class():
    BaseCallbackHandler = _base_callback_handler()

    class _HaloCallbackHandler(BaseCallbackHandler):
        """Records each tool call an agent makes, keyed by LangChain ``run_id``."""

        def __init__(self, recorder, *, category="security", scope=None,
                     session_id="local", agent=None, subject=None,
                     summaries=True):
            self.recorder = recorder
            self.category = category
            self.scope = scope
            self.session_id = session_id
            self.agent = agent
            self.subject = subject
            self.summaries = summaries
            self._pending = {}

        def on_tool_start(self, serialized, input_str, *, run_id=None, **kwargs):
            name = (serialized or {}).get("name") or "tool"
            self._pending[run_id] = {"tool": name, "input": input_str}

        def on_tool_end(self, output, *, run_id=None, **kwargs):
            self._emit(run_id, output=output)

        def on_tool_error(self, error, *, run_id=None, **kwargs):
            self._emit(run_id, error=error)

        def _emit(self, run_id, output=None, error=None):
            pending = self._pending.pop(run_id, None)
            if pending is None:
                return
            try:
                record_tool_call(
                    self.recorder, pending["tool"], pending["input"],
                    response=output, error=error, agent=self.agent or _AGENT,
                    category=self.category, scope=self.scope,
                    session_id=self.session_id, subject=self.subject,
                    source="langchain", summaries=self.summaries)
            except Exception as exc:
                # LangChain's callback manager swallows handler exceptions, so a
                # failed append would otherwise vanish silently — the worst
                # failure mode an evidence recorder can have. Count it and say
                # so loudly; the agent's own action is never interrupted.
                self.lost_records = getattr(self, "lost_records", 0) + 1
                import sys as _sys
                _sys.stderr.write(
                    "halo-record: FAILED to append record for tool %r (%s) — "
                    "this action is NOT in the evidence log (lost so far: %d)\n"
                    % (pending.get("tool"), exc, self.lost_records))

    return _HaloCallbackHandler


def __getattr__(name):
    # Lazily materialize the handler class on first access so that merely
    # importing this module does not require langchain to be installed.
    if name == "HaloCallbackHandler":
        return _build_handler_class()
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
