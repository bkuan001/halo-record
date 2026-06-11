"""One-line agent instrumentation.

    from halo import trace

    agent = trace(run, profile="acme-support")
    agent(...)            # every recorded tool call inside is now on the chain

``trace`` wraps your agent's entrypoint. For the duration of each call it binds
a profile-scoped :class:`~halo_record.record.Recorder` as the *active* recorder,
so every Halo-instrumented tool call made inside — the ``@record`` decorator,
``record_call``, or any adapter in :mod:`halo_record.integrations` — lands on
the profile's hash-chained log without a recorder being threaded through. The
agent's own invocation boundary (its call and outcome) is recorded too, so even
an uninstrumented agent produces a real, verifiable Record from one import.

It does not change what your agent returns, and it never swallows exceptions: a
raised error is recorded as the boundary outcome and then re-raised.

Storage:
  - default            ``~/.halo/<profile>.jsonl`` (one chain for the agent)
  - ``log=PATH``       an explicit single-chain path
  - ``dir=PATH``       per-tenant routing — each ``subject`` to its own chain,
                       exactly what ``halo serve`` expects (multi-customer vendor)
"""

import functools
import os

from .capture import derive_outcome
from .record import Recorder, TenantRecorder, build
from .session import bind_recorder, current_recorder, reset_recorder

DEFAULT_HOME = "~/.halo"


def _safe(name):
    cleaned = "".join(
        c if (c.isalnum() or c in "-_.") else "_" for c in str(name)
    ).strip("._")
    return cleaned or "agent"


def _make_recorder(profile, log, directory):
    if directory is not None:
        directory = os.path.expanduser(directory)
        os.makedirs(directory, exist_ok=True)
        return TenantRecorder(directory)
    if log is None:
        home = os.path.expanduser(DEFAULT_HOME)
        os.makedirs(home, exist_ok=True)
        log = os.path.join(home, _safe(profile) + ".jsonl")
    else:
        log = os.path.expanduser(log)
        parent = os.path.dirname(log)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
    return Recorder(log)


def trace(fn=None, *, profile, log=None, dir=None, subject=None,
          category="security", agent=None, summaries=True, record_boundary=True):
    """Wrap an agent entrypoint so its run produces a Halo Runtime Record.

    Usable directly — ``trace(run, profile="acme")`` — or as a decorator with
    keyword args — ``@trace(profile="acme")``. The wrapped callable carries the
    bound recorder on its ``halo_recorder`` attribute for inspection/verify.
    """
    recorder = _make_recorder(profile, log, dir)
    agent_meta = agent or {"id": profile, "name": profile}

    def wrap(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            token = bind_recorder(recorder)
            result = None
            error = None
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as exc:  # record the boundary, never swallow
                error = exc
                raise
            finally:
                if record_boundary:
                    outcome = derive_outcome(result, error=error)
                    # Boundary marker only — arg *shape*, never raw payloads.
                    boundary_input = {
                        "args": len(args),
                        "kwargs": sorted(kwargs.keys()),
                    }
                    rec = build(
                        "agent_message", category, tool=profile,
                        tool_input=boundary_input, agent=agent_meta,
                        subject=subject, outcome=outcome, summaries=summaries,
                    )
                    recorder.append(rec)
                reset_recorder(token)

        wrapper.halo_recorder = recorder
        return wrapper

    return wrap(fn) if fn is not None else wrap
