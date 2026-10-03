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


# --------------------------------------------------------------------------- #
# When a record cannot be written
# --------------------------------------------------------------------------- #

# Records are written after the action runs. If writing one fails, the wrappers
# (record_call, @record, trace, the framework adapters, the MCP wrapper, the
# Claude Code hook) pass the action's own result or error through unchanged and
# say on stderr which record is missing: raising instead would make a completed
# action look failed, and a retry would repeat its side effects. Strict mode
# also raises the recording error, after the same stderr line, for callers that
# prefer an error to a missing record and accept that risk. Where a framework
# catches what its callbacks raise (OpenTelemetry's span processors, LiteLLM's
# logging), the error cannot reach the caller and the line is the signal.
STRICT_RECORDING_ENV = "HALO_STRICT_RECORDING"


def strict_recording(value=None):
    """Whether a recording failure raises: ``value`` when it is given, else the
    ``HALO_STRICT_RECORDING`` environment variable (1 / true / yes)."""
    if value is not None:
        return bool(value)
    import os
    return os.environ.get(STRICT_RECORDING_ENV, "").strip().lower() in ("1", "true", "yes")


def _warn(line):
    """Write ``line`` to stderr; when there is no usable stderr (pythonw, a
    closed fd 2), log it on the ``halo_record`` logger instead. Never raises:
    a missing stderr must not cost the action's result."""
    import sys
    stream = sys.stderr
    if stream is not None:
        try:
            stream.write(line)
            return
        except Exception:
            pass
    try:
        import logging
        logging.getLogger("halo_record").warning(line.rstrip("\n"))
    except Exception:
        pass


def recording_failed(what, exc, strict=None, note=""):
    """Handle ``exc``, raised while recording ``what`` after the action ran.

    The Halo warning line is always written first (to stderr, or the
    ``halo_record`` logger when there is no usable stderr). Then strict mode
    raises ``exc``; otherwise this returns and the action's own result or
    error passes through."""
    strict = strict_recording(strict)
    if strict:
        tail = ("Strict recording is on (%s / strict_recording=True): the recording error "
                "is raised; the action has already run, so do not retry it blindly."
                % STRICT_RECORDING_ENV)
    else:
        tail = ("The action's own result or error is passed through unchanged "
                "(set %s=1 to raise instead)." % STRICT_RECORDING_ENV)
    _warn("halo-record: FAILED to record %r (%s: %s); the action ran, but its record is "
          "NOT in the evidence log. %s%s\n" % (what, type(exc).__name__, exc, tail, note))
    if strict:
        raise exc
