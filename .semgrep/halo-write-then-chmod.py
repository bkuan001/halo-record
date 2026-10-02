import os
from pathlib import Path

def bad1(path, key):
    # ruleid: halo-write-then-chmod
    with open(path, "w") as f:
        f.write(key)
    os.chmod(path, 0o600)

def bad2(path, key):
    # ruleid: halo-write-then-chmod
    f = open(path, "wb")
    f.write(key)
    f.close()
    os.chmod(path, 0o600)

def bad3(p: Path, key):
    # ruleid: halo-write-then-chmod
    p.write_text(key)
    p.chmod(0o600)

def bad4(path, key):
    # ruleid: halo-write-then-chmod
    with open(path, "w", encoding="utf-8") as f:
        f.write(key)
        os.chmod(path, 0o600)

def good(path, key):
    # ok: halo-write-then-chmod
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)

def good2(path):
    # ok: halo-write-then-chmod
    with open(path, "w") as f:
        f.write("public")
    os.chmod(path, 0o644)
