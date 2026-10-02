"""Owner-only file creation for secrets, keys, and access lists."""

import os


def open_private(path, mode="w", encoding="utf-8"):
    """Open ``path`` for writing with owner-only permissions from creation.

    The file is created with mode 0600 in the same call that opens it, so there
    is no moment when it exists with the process umask's wider permissions. An
    existing file is tightened to 0600 as well."""
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (AttributeError, OSError):
        pass
    try:
        if "b" in mode:
            return os.fdopen(fd, mode)
        return os.fdopen(fd, mode, encoding=encoding)
    except Exception:
        os.close(fd)
        raise
