"""Build and append Halo Runtime Records (Schema v0.1).

``Recorder`` appends conformant, hash-chained records to a JSONL log. ``build``
constructs a single record dict without writing it. Both redact sensitive data
and never store raw secrets.
"""

import json
import os
import threading
import uuid
from datetime import datetime, timezone

try:  # POSIX inter-process append lock; on other platforms appends are
    import fcntl  # serialized per-process only (the threading.Lock below).
except ImportError:  # pragma: no cover
    fcntl = None

from .canon import GENESIS_PREV, compute_hash, input_hash
from .redact import redact_text, scan, top_severity

SCHEMA_VERSION = "0.1"

ACTION_TYPES = {"tool_call", "agent_message", "read", "write", "network"}
CATEGORIES = {"security", "safety", "reliability", "privacy"}

# Where a record came from. ``capture`` is the honest evidentiary tier:
#   "captured"  — Halo saw the call at the trust boundary (in-process interceptor
#                 or the native recorder). Strongest: nothing could be shaped
#                 before Halo recorded it.
#   "ingested"  — the record was built from telemetry the vendor already emits
#                 (OTel spans, gateway/proxy logs, a tracing store). Useful and
#                 low-friction, but weaker: the stream is the vendor's own, so the
#                 witness attests "this is what you sent me", not "I watched it happen".
# This distinction is the product's honesty: an independent attestor discloses
# provenance and strength per record rather than flattening every source to "logged".
SOURCES = {
    "recorder":      {"adapter": "recorder",      "via": "Halo recorder (native)",        "capture": "captured"},
    "mcp":           {"adapter": "mcp",           "via": "MCP interceptor",               "capture": "captured"},
    "langchain":     {"adapter": "langchain",     "via": "LangChain / LangGraph",         "capture": "captured"},
    "openai_agents": {"adapter": "openai_agents", "via": "OpenAI Agents SDK",             "capture": "captured"},
    "vercel_ai":     {"adapter": "vercel_ai",     "via": "Vercel AI SDK",                 "capture": "captured"},
    "claude_agent_sdk": {"adapter": "claude_agent_sdk", "via": "Claude Agent SDK",        "capture": "captured"},
    "otel":          {"adapter": "otel",          "via": "OpenTelemetry GenAI spans",     "capture": "ingested"},
    "litellm":       {"adapter": "litellm",       "via": "LiteLLM gateway",               "capture": "ingested"},
    "langfuse":      {"adapter": "langfuse",      "via": "Langfuse traces",               "capture": "ingested"},
    "gateway":       {"adapter": "gateway",       "via": "LLM gateway / proxy log",       "capture": "ingested"},
}


def normalize_source(source):
    """Resolve a source spec into a ``{adapter, via, capture}`` dict.

    Accepts a known adapter id (str), a custom dict, or None. An unknown id is
    kept verbatim and assumed ``ingested`` — the conservative (weaker) tier, so
    an unrecognized origin is never overstated as boundary-captured."""
    if source is None:
        return None
    if isinstance(source, str):
        return dict(SOURCES.get(source, {"adapter": source, "via": source, "capture": "ingested"}))
    src = dict(source)
    src.setdefault("capture", "ingested")
    src.setdefault("via", src.get("adapter", "unknown"))
    return src


def _now():
    return datetime.now(timezone.utc).isoformat()


def _norm_subject(subject):
    if subject is None:
        return None
    if isinstance(subject, str):
        return {"id": subject}
    return subject


_PRINCIPAL_KEYS = ("human_id", "creator_id", "service_account", "role_scope")


def _norm_principal(principal):
    """Keep only the four schema-defined principal layers; drop unknown keys and
    empty values. Returns None if nothing usable remains."""
    if principal is None:
        return None
    if not isinstance(principal, dict):
        return None
    out = {k: str(principal[k]) for k in _PRINCIPAL_KEYS
           if principal.get(k) not in (None, "")}
    return out or None


def _norm_threats(threats):
    """Normalize ingested threats into schema shape ([{type, ref?}]).

    Threats are INGESTED from an upstream guardrail/detector — Halo records that
    a threat was flagged, it does not itself judge or detect. Accepts a list of
    bare type strings and/or ``{type, ref?}`` dicts; a single bare string is
    read as one threat (so ``threats="prompt_injection"`` is not iterated
    character by character). Dicts without a ``type`` are dropped.
    """
    if not threats:
        return None
    if isinstance(threats, str) or isinstance(threats, dict):
        threats = [threats]          # a single string or dict is one threat
    elif not isinstance(threats, (list, tuple)):
        return None                  # unrecognized scalar (int, etc.): drop, never
                                     # raise — instrumentation must not crash a tool
    out = []
    for t in threats:
        if isinstance(t, str):
            if t:
                out.append({"type": t})
        elif isinstance(t, dict) and t.get("type"):
            item = {"type": str(t["type"])}
            if t.get("ref") not in (None, ""):
                item["ref"] = str(t["ref"])
            out.append(item)
    return out or None


# Which redaction finding types are personal data (vs. secrets/credentials).
# ``data.pii_types`` is DERIVED from what the deterministic scanner already
# found — no separate detector, no model judgement. This is the scanner's set
# of *named* personal-data categories, not a claim of comprehensive PII
# coverage: free-form data with no fixed shape (a name, a postal address) has
# no reliable pattern and never appears here (see LIMITS.md).
_PII_FINDING_TYPES = {"email", "ssn", "credit_card", "phone", "iban"}


def _pii_types_from_findings(findings):
    """Distinct personal-data categories detected in this record's findings."""
    types = sorted({f.get("type") for f in findings
                    if f.get("type") in _PII_FINDING_TYPES})
    return types or None


def build(action_type, category, tool=None, tool_input=None, *,
          session_id="local", agent=None, scope=None, decision="allowed",
          approver=None, findings=None, outcome=None, ts=None,
          subject=None, source=None, authority=None, summaries=True,
          principal=None, parent_id=None, threats=None, data=None):
    """Construct a v0.1 record (without integrity.hash filled in).

    ``tool_input`` is hashed (canonical) and, by default, a redacted summary is
    stored; raw arguments never enter the record. If ``findings`` is None and
    ``tool_input`` is given, the input is scanned automatically.

    ``subject`` (a str id or ``{"id", "name"}`` dict) tags the record with the
    tenant/customer it belongs to — the segmentation key. ``authority`` may carry
    a privacy-safe snapshot of the rules/tooling context that governed the run
    (hashes and refs, not raw prompts or private policy text). ``summaries=False``
    drops every human-readable summary, leaving only hashes: a hash-only record
    safe to share across a trust boundary, since no payload text is stored.

    ``principal`` records the identities on whose behalf the action ran
    (``human_id`` / ``creator_id`` / ``service_account`` / ``role_scope``);
    ``parent_id`` links this record to the one that caused it (delegation /
    sub-agent chains); ``halo verify`` reports whether each link resolves within
    the chain. ``threats`` is an INGESTED set of flags from an upstream
    guardrail/detector — a list of ``{"type": ..., "ref": ...}`` dicts and/or
    bare type strings, or a single string or dict — Halo records that a threat
    was flagged, it never judges or detects one itself. ``data`` carries
    request-context fields (``region`` str / ``cross_region`` numeric 0|1 /
    ``purpose`` str; a boolean ``cross_region`` is coerced to 0/1);
    ``data.pii_types`` is filled automatically from the deterministic scanner's
    named personal-data categories (email, ssn, credit_card, phone, iban), which
    is not comprehensive PII coverage — see LIMITS.md.
    """
    if action_type not in ACTION_TYPES:
        raise ValueError("action.type must be one of %s" % sorted(ACTION_TYPES))
    if category not in CATEGORIES:
        raise ValueError("action.category must be one of %s" % sorted(CATEGORIES))

    action = {"type": action_type, "category": category}
    if tool is not None:
        action["tool"] = tool
    if scope is not None or decision is not None:
        auth = {"decision": decision}
        if scope is not None:
            auth["scope"] = scope
        if approver is not None:
            auth["approver"] = approver
        action["authorization"] = auth
    if tool_input is not None:
        inp = {"hash": input_hash(tool_input)}
        if summaries:
            inp["summary"] = redact_text(str(tool_input))[:200]
        action["input"] = inp

    # Normalize the outcome up front so its summary is redacted before it is
    # sealed/served and so it can be scanned for secrets alongside the input.
    outcome_summary_raw = None
    if outcome is not None:
        outcome = dict(outcome)
        if "summary" in outcome and outcome["summary"] is not None:
            outcome_summary_raw = str(outcome["summary"])
        if not summaries:
            outcome.pop("summary", None)
        elif outcome_summary_raw is not None:
            outcome["summary"] = redact_text(outcome_summary_raw)[:200]

    if findings is None:
        findings = []
        if tool_input is not None:
            findings += scan(str(tool_input))
        if outcome_summary_raw is not None:
            findings += scan(outcome_summary_raw)
    findings = findings or []

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": str(uuid.uuid4()),
        "session_id": session_id,
        "ts": ts or _now(),
        "agent": agent or {"id": "unknown", "name": "unknown"},
        "action": action,
        "severity": top_severity(findings),
        "findings": findings,
        "integrity": {
            "alg": "sha-256",
            "canon": "rfc8785",
            "prev_hash": "",
            "hash": "",
        },
    }
    subject = _norm_subject(subject)
    if subject is not None:
        record["subject"] = subject
    principal = _norm_principal(principal)
    if principal is not None:
        record["principal"] = principal
    if parent_id is not None and str(parent_id) != "":
        record["parent_id"] = str(parent_id)
    source = normalize_source(source)
    if source is not None:
        record["source"] = source
    if authority is not None:
        record["authority"] = dict(authority)
    threats = _norm_threats(threats)
    if threats is not None:
        record["threats"] = threats
    # data.pii_types is derived from the scanner's personal-data findings and
    # merged with any caller-supplied request-context (region/purpose/...).
    data_block = dict(data) if isinstance(data, dict) else {}
    # cross_region is a numeric field (0/1); coerce the intuitive boolean so a
    # caller passing True never seals a schema-invalid record into the chain.
    if isinstance(data_block.get("cross_region"), bool):
        data_block["cross_region"] = int(data_block["cross_region"])
    pii_types = _pii_types_from_findings(findings)
    if pii_types is not None:
        data_block["pii_types"] = pii_types
    if data_block:
        record["data"] = data_block
    if outcome is not None:
        record["outcome"] = outcome
    return record


def _read_last_line(path):
    """Last non-empty line of ``path``, read from the tail without scanning the
    whole file. Falls back to a full scan only if the final line is longer than
    the tail window (records are ~1 KB; the window is 256 KB)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return None
            back = min(size, 262144)
            fh.seek(size - back)
            buf = fh.read(back)
        stripped = buf.rstrip()
        if stripped:
            nl = stripped.rfind(b"\n")
            if nl != -1:
                return stripped[nl + 1:]
            if back == size:
                return stripped  # single-line file, fully in the window
        elif back == size:
            return None  # whitespace-only file
    except OSError:
        return None
    last = None
    with open(path, "rb") as fh:
        for line in fh:
            if line.strip():
                last = line
    return last


class Recorder:
    """Append-only writer that maintains the hash chain in a JSONL file.

    Appends are serialized both within a process (threading.Lock — agents call
    tools in parallel) and across processes (an ``fcntl`` lock on a ``.lock``
    sidecar file, POSIX) — hook-style capture spawns one short-lived process
    per tool call, and two of those appending at once must not both extend the
    same chain head. The head is cached per instance and re-read from disk
    whenever the file has grown underneath the cache.
    """

    def __init__(self, path):
        self.path = os.path.expanduser(path)
        self._lock = threading.Lock()
        self._last_hash = None
        self._last_authority_snapshot_id = None
        self._tail_loaded = False
        self._last_size = None

    def _acquire_flock(self):
        if fcntl is None:
            return None
        fh = open(self.path + ".lock", "ab")
        fcntl.flock(fh, fcntl.LOCK_EX)
        return fh

    @staticmethod
    def _release_flock(fh):
        if fh is None:
            return
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()

    def _size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _refresh_tail(self):
        """Read the chain head (and last authority snapshot) from disk."""
        line = _read_last_line(self.path) if os.path.exists(self.path) else None
        self._last_hash = GENESIS_PREV
        self._last_authority_snapshot_id = None
        if line is not None:
            try:
                rec = json.loads(line)
                self._last_hash = rec.get("integrity", {}).get("hash") or GENESIS_PREV
                authority = rec.get("authority")
                if isinstance(authority, dict):
                    self._last_authority_snapshot_id = authority.get("snapshot_id")
            except Exception:
                pass
        self._last_size = self._size()
        self._tail_loaded = True

    def _current_tail(self):
        """Chain head + authority snapshot id, re-reading from disk if another
        process has appended since this instance last looked."""
        if not self._tail_loaded or self._size() != self._last_size:
            self._refresh_tail()
        return self._last_hash, self._last_authority_snapshot_id

    def last_hash(self):
        with self._lock:
            return self._current_tail()[0]

    def last_authority_snapshot_id(self):
        with self._lock:
            return self._current_tail()[1]

    @staticmethod
    def _dedupe_authority(record, previous_snapshot_id):
        authority = record.get("authority")
        if not isinstance(authority, dict):
            return None
        snapshot_id = authority.get("snapshot_id")
        if snapshot_id and snapshot_id == previous_snapshot_id:
            record["authority"] = {
                "snapshot_id": snapshot_id,
                "same_as_previous": True,
            }
        return snapshot_id

    def append(self, record):
        with self._lock:
            flock = self._acquire_flock()
            try:
                prev, prev_snapshot_id = self._current_tail()
                authority_snapshot_id = self._dedupe_authority(record, prev_snapshot_id)
                record.setdefault("integrity", {})
                record["integrity"]["prev_hash"] = prev
                record["integrity"]["hash"] = compute_hash(record, prev)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
                    fh.flush()
                    self._last_size = fh.tell()
                self._last_hash = record["integrity"]["hash"]
                self._last_authority_snapshot_id = authority_snapshot_id
            finally:
                self._release_flock(flock)
        return record


class TenantRecorder:
    """Routes each record to a per-subject log, each its own hash chain.

    A single instrumented agent serving many customers keeps every customer's
    records physically isolated: record for subject ``acme-corp`` lands in
    ``<directory>/acme-corp.jsonl``, ``initech`` in its own file, each an
    independent, standalone-verifiable chain. Sharing a customer's report means
    sharing only their file — other tenants are invisible by construction, not
    by filtering. Records with no subject go to ``<directory>/<default>.jsonl``.
    """

    def __init__(self, directory, *, default="_local"):
        self.directory = os.path.expanduser(directory)
        self.default = default
        self._recorders = {}

    @staticmethod
    def _safe(name):
        cleaned = "".join(
            c if (c.isalnum() or c in "-_.") else "_" for c in str(name)
        ).strip("._")
        return cleaned or "tenant"

    def _subject_id(self, record):
        subj = record.get("subject")
        if isinstance(subj, dict) and subj.get("id"):
            return subj["id"]
        return self.default

    def path_for(self, subject_id):
        return os.path.join(self.directory, self._safe(subject_id) + ".jsonl")

    def recorder_for(self, subject_id):
        if subject_id not in self._recorders:
            if not os.path.isdir(self.directory):
                os.makedirs(self.directory, exist_ok=True)
            self._recorders[subject_id] = Recorder(self.path_for(subject_id))
        return self._recorders[subject_id]

    def append(self, record):
        return self.recorder_for(self._subject_id(record)).append(record)
