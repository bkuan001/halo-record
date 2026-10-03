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

A record that cannot be written is reported on stderr and the tool's result
passes through. With ``strict_recording=True`` (or ``HALO_STRICT_RECORDING=1``)
the handler sets LangChain's ``raise_error``, so the recording error is raised
to the caller of the tool, after the same stderr line.
"""

from ..session import recording_failed, strict_recording
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
                     summaries=True, strict_recording=None):
            self.recorder = recorder
            self.strict_recording = strict_recording
            self.category = category
            self.scope = scope
            self.session_id = session_id
            self.agent = agent
            self.subject = subject
            self.summaries = summaries
            self.lost_records = 0
            self._pending = {}

        @property
        def raise_error(self):
            # LangChain's callback manager logs and drops what a handler
            # raises unless the handler sets raise_error. In strict mode it is
            # set, so the recording error reaches the caller of the tool.
            return strict_recording(self.strict_recording)

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
                # LangChain's callback manager swallows handler exceptions unless
                # raise_error is set, so a failed append would otherwise vanish
                # silently. Count it and say so loudly; in strict mode the error
                # is then raised, and raise_error carries it to the caller.
                self.lost_records = getattr(self, "lost_records", 0) + 1
                recording_failed(pending.get("tool"), exc, self.strict_recording,
                                 " (lost so far: %d)" % self.lost_records)

    return _HaloCallbackHandler


def __getattr__(name):
    # Lazily materialize the handler class on first access so that merely
    # importing this module does not require langchain to be installed.
    if name == "HaloCallbackHandler":
        return _build_handler_class()
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
