"""``from halo import trace`` — the one-import front door.

The package is :mod:`halo_record`; this thin shim lets the hero snippet read
exactly as advertised::

    from halo import trace

    agent = trace(run, profile="acme-support")
    agent(...)

Everything re-exported here lives in and is documented under ``halo_record``;
this module adds no behavior, only the shorter name.
"""

from halo_record import *  # noqa: F401,F403
from halo_record import __all__ as _all
from halo_record import __version__

__all__ = list(_all)
