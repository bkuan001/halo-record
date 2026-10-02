"""OpenAI Agents SDK adapter.

Pass ``HaloRunHooks`` to ``Runner.run`` and every tool the agent invokes is
recorded as a Halo Runtime Record:

    from halo_record import Recorder
    from halo_record.integrations.openai_agents import HaloRunHooks
    from agents import Runner

    await Runner.run(agent, input, hooks=HaloRunHooks(Recorder("audit.jsonl")))

The handler subclasses the SDK's ``RunHooks``. The ``agents`` package is imported
lazily so it is only required when this adapter is actually used. Recording is
best-effort and never interferes with the run.
"""

from ..session import recording_failed
from ._common import record_tool_call

_AGENT = {"id": "openai-agents", "name": "openai-agents"}


def _run_hooks_base():
    try:
        from agents import RunHooks
    except ImportError as exc:  # pragma: no cover - SDK not installed
        raise ImportError(
            "HaloRunHooks requires the OpenAI Agents SDK. "
            "Install with: pip install openai-agents"
        ) from exc
    return RunHooks


def _tool_name(tool):
    return getattr(tool, "name", None) or getattr(tool, "__name__", None) or "tool"


def _build_hooks_class():
    RunHooks = _run_hooks_base()

    class _HaloRunHooks(RunHooks):
        """Records each tool call, keyed by the tool object between start/end."""

        def __init__(self, recorder, *, category="security", scope=None,
                     session_id="local", agent=None, subject=None,
                     summaries=True, strict_recording=None):
            self.recorder = recorder
            self.strict_recording = strict_recording
            self.category = category
            self.scope = scope
            self.session_id = session_id
            self.agent = agent or _AGENT
            self.subject = subject
            self.summaries = summaries
            self._pending = {}

        async def on_tool_start(self, context, agent, tool):
            self._pending[id(tool)] = _tool_name(tool)

        async def on_tool_end(self, context, agent, tool, result):
            name = self._pending.pop(id(tool), None) or _tool_name(tool)
            # The tool has already run; a recording failure is reported, not
            # raised into the run (unless strict_recording).
            try:
                record_tool_call(
                    self.recorder, name, None, response=result, agent=self.agent,
                    category=self.category, scope=self.scope,
                    session_id=self.session_id, subject=self.subject,
                    source="openai_agents", summaries=self.summaries)
            except Exception as exc:
                recording_failed(name, exc, self.strict_recording)

    return _HaloRunHooks


def __getattr__(name):
    if name == "HaloRunHooks":
        return _build_hooks_class()
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
