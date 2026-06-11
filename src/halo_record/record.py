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


def build(action_type, category, tool=None, tool_input=None, *,
          session_id="local", agent=None, scope=None, decision="allowed",
          approver=None, findings=None, outcome=None, ts=None,
          subject=None, source=None, summaries=True):
    """Construct a v0.1 record (without integrity.hash filled in).

    ``tool_input`` is hashed (canonical) and, by default, a redacted summary is
    stored; raw arguments never enter the record. If ``findings`` is None and
    ``tool_input`` is given, the input is scanned automatically.

    ``subject`` (a str id or ``{"id", "name"}`` dict) tags the record with the
    tenant/customer it belongs to — the segmentation key. ``summaries=False``
    drops every human-readable summary, leaving only hashes: a hash-only record
    safe to share across a trust boundary, since no payload text is stored.
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
    source = normalize_source(source)
    if source is not None:
        record["source"] = source
    if outcome is not None:
        record["outcome"] = outcome
    return record


class Recorder:
    """Append-only writer that maintains the hash chain in a JSONL file.

    Appends are thread-safe within a process (agents call tools in parallel),
    and the chain head is cached after the first read so appending stays O(1)
    per record instead of re-scanning the file. One Recorder instance should
    own a given log file per process — that is also the TenantRecorder model.
    """

    def __init__(self, path):
        self.path = os.path.expanduser(path)
        self._lock = threading.Lock()
        self._last_hash = None

    def last_hash(self):
        if self._last_hash is not None:
            return self._last_hash
        if not os.path.exists(self.path):
            return GENESIS_PREV
        last = None
        with open(self.path, "rb") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return GENESIS_PREV
        try:
            rec = json.loads(last)
            return rec.get("integrity", {}).get("hash") or GENESIS_PREV
        except Exception:
            return GENESIS_PREV

    def append(self, record):
        with self._lock:
            prev = self.last_hash()
            record.setdefault("integrity", {})
            record["integrity"]["prev_hash"] = prev
            record["integrity"]["hash"] = compute_hash(record, prev)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._last_hash = record["integrity"]["hash"]
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
