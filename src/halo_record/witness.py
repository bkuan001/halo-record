"""The hosted Halo witness — the neutral notary as a network service.

A per-tenant hash chain is internally tamper-evident, but a vendor who hosts
their *own* chain can drop a record and rebuild a chain that still verifies
(see ``anchor`` for the full argument). The fix is an append-only witness the
vendor does not control. ``anchor.Notary`` is that store on disk; this module
puts it behind HTTP so vendors anchor to a witness running in *Halo's* account,
not their own — which is what makes "complete" a claim the buyer's security
team can trust instead of taking on the vendor's word.

Trust-not-data, by construction:
  The vendor computes the checkpoint LOCALLY and POSTs only
  ``{subject, count, head, chain_root}`` — opaque hashes, a count, and the
  customer id. Record *contents* never leave the vendor. Halo witnesses what it
  saw (a head at a count at a time) without ever holding the underlying runtime
  data. The independence comes from Halo hosting an append-only log the vendor
  can't rewrite, not from Halo accumulating the vendor's data.

Routes:
  POST /anchor                  vendor-authed (Bearer key); append one checkpoint,
                                return a receipt. Append-only — no update/delete.
  GET  /v1/checkpoints?subject= public, CORS-open so a viewer's browser can fetch
                                the witness log while verifying a report.
  GET  /healthz                 liveness probe.

Pure-stdlib, like the rest of the package. Offline *signed* receipts (so a buyer
can verify a witness without contacting Halo) need asymmetric signatures and are
deliberately deferred; the hosted append-only store is the guarantee on its own.
"""

import fnmatch
import hashlib
import hmac
import json
import threading
import os
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

from . import __version__
from .anchor import Notary, checkpoint, _now

WITNESS_FILE = "witness.jsonl"
OWNERS_FILE = "witness_owners.json"
KEY_FILE = ".halo_witness_key"
MAX_BODY = 8192
DEFAULT_PORT = 8730

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SUBJECT_RE = re.compile(r"^[\w.\- ]{1,200}$")


def load_keys(store):
    """Vendor bearer keys authorized to anchor. ``$HALO_WITNESS_KEYS`` (comma-
    separated) if set, else a single random key persisted in the store so it
    survives restarts. Several vendors can share one witness, each with its own
    key; scope a key with ``<key>=<subject-or-glob>|…`` (for example
    ``k1=vendor-a-*,k2=vendor-b-*``). Whether scoped or not, a key can only add
    checkpoints to subjects it anchored first. Returns ``[(key, scopes), …]``."""
    env = os.environ.get("HALO_WITNESS_KEYS")
    if env:
        return parse_key_spec(env.split(","))
    path = os.path.join(store, KEY_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return parse_key_spec(fh.read().splitlines())
    key = os.urandom(24).hex()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    os.chmod(path, 0o600)
    return parse_key_spec([key])


def parse_key_spec(entries):
    """Parse authorized vendor keys. Each entry is ``<key>`` or
    ``<key>=<scope>|<scope>…``, where a scope is a subject ID or a glob
    (``vendor-a-*``). Returns ``[(key, scopes_or_None), …]``. A scoped key may
    anchor only subjects its scopes match; every key, scoped or not, may only
    extend subjects it anchored first (see ``_Handler``)."""
    out = []
    for raw in entries:
        if isinstance(raw, tuple):
            out.append(raw)
            continue
        entry = str(raw).strip()
        if not entry:
            continue
        key, _, spec = entry.partition("=")
        scopes = [x.strip() for x in spec.split("|") if x.strip()] if spec else None
        out.append((key.strip(), scopes))
    return out


def _key_match(presented, keys):
    """Constant-time match of a presented bearer key. Returns the matching
    ``(key, scopes)`` entry, or None."""
    if not presented:
        return None
    found = None
    for entry in parse_key_spec(keys):
        if hmac.compare_digest(presented, entry[0]):
            found = entry
    return found


def _key_ok(presented, keys):
    """Constant-time match of a presented bearer key against any authorized key."""
    return _key_match(presented, keys) is not None


def _in_scope(subject, scopes):
    if scopes is None:
        return True
    if subject is None:
        return False
    return any(fnmatch.fnmatchcase(subject, sc) for sc in scopes)


def _fingerprint(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _clean_checkpoint(payload):
    """Validate and normalize a posted checkpoint. Returns a sanitized dict or
    raises ValueError. Only the four attesting fields are accepted; the server
    stamps its own ``ts`` (a vendor cannot backdate a witness)."""
    if not isinstance(payload, dict):
        raise ValueError("checkpoint must be a JSON object")
    subject = payload.get("subject")
    if subject is not None:
        if not isinstance(subject, str) or not _SUBJECT_RE.match(subject):
            raise ValueError("invalid subject")
    count = payload.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError("count must be a positive integer")
    head = payload.get("head")
    if not isinstance(head, str) or not _HEX64.match(head):
        raise ValueError("head must be a 64-char sha-256 hex digest")
    chain_root = payload.get("chain_root")
    if chain_root is not None and not (
            isinstance(chain_root, str) and _HEX64.match(chain_root)):
        raise ValueError("chain_root must be a 64-char sha-256 hex digest")
    return {
        "chain_root": chain_root,
        "subject": subject,
        "count": count,
        "head": head,
        "ts": _now(),
    }


# --- client side: a vendor anchors a chain head to the hosted witness ----------

def anchor_remote(witness_url, key, records, *, timeout=10):
    """Anchor a chain's current head to a hosted Halo witness.

    The checkpoint is computed LOCALLY and only ``{subject, count, head,
    chain_root}`` is sent — record contents never leave the vendor. Returns the
    witness's receipt (the stored checkpoint with Halo's server timestamp)."""
    cp = checkpoint(records)
    body = json.dumps({k: cp[k] for k in ("subject", "count", "head", "chain_root")},
                      separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        witness_url.rstrip("/") + "/anchor", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    return out.get("receipt", out)


def fetch_checkpoints(witness_url, subject=None, *, timeout=10):
    """Fetch the witness's independently held checkpoints for a subject. This is
    what a viewer's browser (or a buyer's tooling) calls to check completeness
    against a party the vendor does not control."""
    url = witness_url.rstrip("/") + "/v1/checkpoints"
    if subject is not None:
        url += "?" + urlencode({"subject": subject})
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    return out.get("checkpoints", [])


class _Handler(BaseHTTPRequestHandler):
    server_version = "halo-witness/" + __version__
    config = None  # injected: {"notary","keys"}

    def _send(self, code, body, ctype="application/json; charset=utf-8", cors=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":"))
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if parsed.path == "/v1/checkpoints":
            subject = (parse_qs(parsed.query).get("subject") or [None])[0]
            # subject is only ever a filter, never a path — traversal impossible.
            cps = self.config["notary"].checkpoints(subject=subject)
            return self._send(200, {"checkpoints": cps, "count": len(cps)}, cors=True)
        return self._send(404, {"error": "not found"})

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path != "/anchor":
            return self._send(404, {"error": "not found"})

        auth = self.headers.get("Authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        entry = _key_match(presented, self.config["keys"])
        if entry is None:
            return self._send(401, {"error": "unauthorized"})

        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            return self._send(413, {"error": "payload too large"})
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
            cp = _clean_checkpoint(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            return self._send(400, {"error": str(exc)})

        if not _in_scope(cp["subject"], entry[1]):
            return self._send(403, {"error": "key not authorized for this subject"})
        with self._lock():
            if not self._claim(cp, entry[0]):
                return self._send(403, {"error": "subject is anchored by another key"})
            receipt = self.config["notary"].record_checkpoint(cp)
        return self._send(201, {"ok": True, "receipt": receipt})

    _default_lock = threading.Lock()

    def _lock(self):
        return self.config.get("lock") or self._default_lock

    def _claim(self, cp, key):
        """First key to anchor a subject owns it; other keys are refused, so one
        vendor cannot append checkpoints to another vendor's chain. Ownership is
        kept beside the witness log (never in the public checkpoints)."""
        path = self.config.get("owners_path")
        if not path:
            return True
        owner_id = cp["subject"] if cp["subject"] is not None else "root:%s" % cp.get("chain_root")
        owners = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                owners = json.load(fh)
        fp = _fingerprint(key)
        held = owners.get(owner_id)
        if held is not None:
            return hmac.compare_digest(held, fp)
        owners[owner_id] = fp
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(owners, fh, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, path)
        return True

    def log_message(self, fmt, *args):
        pass


def serve(store, *, host="127.0.0.1", port=DEFAULT_PORT):
    """Run the hosted witness over ``<store>/witness.jsonl``."""
    store = os.path.expanduser(store)
    if not os.path.isdir(store):
        os.makedirs(store, exist_ok=True)
    notary = Notary(os.path.join(store, WITNESS_FILE))
    keys = load_keys(store)
    handler = type("_BoundWitness", (_Handler,),
                   {"config": {"notary": notary, "keys": keys,
                               "owners_path": os.path.join(store, OWNERS_FILE),
                               "lock": threading.Lock()}})
    httpd = ThreadingHTTPServer((host, port), handler)
    print("Halo witness serving from %s" % os.path.join(store, WITNESS_FILE))
    print("  anchor (vendor): POST http://%s:%s/anchor   (Bearer key required)" % (host, port))
    print("  checkpoints (public): GET http://%s:%s/v1/checkpoints?subject=<id>" % (host, port))
    if not os.environ.get("HALO_WITNESS_KEYS"):
        print("  vendor key: %s" % keys[0][0])
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
