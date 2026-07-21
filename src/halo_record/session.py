"""Ambient recorder binding for one-line instrumentation.

``trace`` (see ``halo_record.trace``) binds a profile-scoped recorder here for
the duration of an agent call. The capture helpers (``record``, ``record_call``)
and the framework adapters fall back to this active recorder when none is passed
explicitly, so a tool deep inside an agent never has to thread a recorder
through every call. Uses ``contextvars`` so concurrent agents (threads / async
tasks) each see their own active recorder.
"""

import contextvars

_ACTIVE = contextvars.ContextVar("halo_active_recorder", default=None)
_ACTIVE_AGENT = contextvars.ContextVar("halo_active_agent", default=None)


def current_agent():
    """The agent identity bound by the nearest enclosing ``trace`` call, or None."""
    return _ACTIVE_AGENT.get()


def bind_agent(agent):
    """Bind ``agent`` metadata as active. Returns a token for ``reset_agent``."""
    return _ACTIVE_AGENT.set(agent)


def reset_agent(token):
    """Restore the previously-bound agent."""
    _ACTIVE_AGENT.reset(token)


def current_recorder():
    """The recorder bound by the nearest enclosing ``trace`` call, or None."""
    return _ACTIVE.get()


def bind_recorder(recorder):
    """Bind ``recorder`` as active. Returns a token for ``reset_recorder``."""
    return _ACTIVE.set(recorder)


def reset_recorder(token):
    """Restore the previously-bound recorder."""
    _ACTIVE.reset(token)
