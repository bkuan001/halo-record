"""Build and append Halo Runtime Records (Schema v0.1).

``Recorder`` appends conformant, hash-chained records to a JSONL log. ``build``
constructs a single record dict without writing it. Both redact sensitive data
and never store raw secrets.
"""

import hashlib
import json
import os
import re
import sys
import threading
import uuid
from datetime import datetime, timezone

try:  # POSIX inter-process append lock; on other platforms appends are
    import fcntl  # serialized per-process only (the threading.Lock below).
except ImportError:  # pragma: no cover
    fcntl = None

from .canon import CIRCULAR, GENESIS_PREV, MAX_DEPTH, TOO_DEEP, canon, compute_hash, input_hash, int_text, json_key, sha256_hex, sort_key
from .redact import CREDENTIAL_MASK, SEVERITY_RANK, credential_value, mask_known_secrets, mask_secrets_only, pseudonymize_secrets, redact_fields, redact_text, scan, scan_fields, top_severity

SCHEMA_VERSION = "0.1"

ACTION_TYPES = {"tool_call", "agent_message", "read", "write", "network"}
CATEGORIES = {"security", "safety", "reliability", "privacy"}

# Where a record came from. ``capture`` is the evidentiary tier:
#   "captured"  — declared recorded at the trust boundary (in-process interceptor
#                 or the native recorder): written as the call runs rather than
#                 rebuilt from other telemetry. The stronger tier; the tag is set
#                 by the integration and not independently verified.
#   "ingested"  — the record was built from telemetry the vendor already emits
#                 (OTel spans, gateway/proxy logs, a tracing store). Useful and
#                 low-friction, but weaker: the stream is the vendor's own, so the
#                 witness attests "this is what you sent me", not "I watched it happen".
# The distinction is disclosed per record: an independent attestor states
# provenance and strength for each record rather than flattening every source to "logged".
SOURCES = {
    "recorder":      {"adapter": "recorder",      "via": "Halo recorder (native)",        "capture": "captured"},
    "mcp":           {"adapter": "mcp",           "via": "MCP interceptor",               "capture": "captured"},
    "langchain":     {"adapter": "langchain",     "via": "LangChain / LangGraph",         "capture": "captured"},
    "openai_agents": {"adapter": "openai_agents", "via": "OpenAI Agents SDK",             "capture": "captured"},
    "vercel_ai":     {"adapter": "vercel_ai",     "via": "Vercel AI SDK",                 "capture": "captured"},
    "claude_agent_sdk": {"adapter": "claude_agent_sdk", "via": "Claude Agent SDK",        "capture": "captured"},
    "hook":          {"adapter": "hook",          "via": "Claude Code PostToolUse hook",  "capture": "ingested"},
    "codex_hook":    {"adapter": "codex_hook",    "via": "Codex CLI PostToolUse hook",    "capture": "ingested"},
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
    if not isinstance(source, dict):
        sys.stderr.write(
            "halo-record: source=%r is not a tag name or mapping; source dropped\n" % (source,))
        return None
    src = dict(source)
    for k in ("adapter", "via"):
        if k in src and src[k] is not None and not isinstance(src[k], str):
            src[k] = str(src[k])
    if not src.get("adapter"):
        sys.stderr.write("halo-record: source has no adapter name; source dropped\n")
        return None
    src.setdefault("capture", "ingested")
    src.setdefault("via", src.get("adapter", "unknown"))
    if not isinstance(src["capture"], str) or src["capture"] not in CAPTURE_TIERS:
        # The verifier rejects any other tier, so sealing it would poison an
        # append-only chain with a record that can never verify. Drop the tier
        # claim loudly rather than guess one; the record seals without a source.
        sys.stderr.write(
            "halo-record: source.capture=%r is not one of %s; source dropped "
            "(the record seals without a provenance tag)\n"
            % (src["capture"], sorted(CAPTURE_TIERS)))
        return None
    return src


def _now():
    return datetime.now(timezone.utc).isoformat()


def _norm_subject(subject):
    if subject is None:
        return None
    if isinstance(subject, str):
        return {"id": subject}
    if isinstance(subject, dict):
        out = dict(subject)
        for k in ("id", "name"):
            v = out.get(k)
            if v is None or isinstance(v, str):
                continue
            if isinstance(v, (int, float, bool)):
                out[k] = str(v)
            else:
                sys.stderr.write("halo-record: subject.%s=%r is not a scalar; subject dropped\n" % (k, v))
                return None
        return out
    sys.stderr.write("halo-record: subject=%r is not a string or mapping; dropped\n" % (subject,))
    return None


_PRINCIPAL_KEYS = ("human_id", "creator_id", "service_account", "role_scope")


def _norm_principal(principal):
    """Keep only the four schema-defined principal layers; drop unknown keys and
    empty values. Returns None if nothing usable remains."""
    if principal is None:
        return None
    if not isinstance(principal, dict):
        return None
    dropped = sorted(str(k) for k in principal if k not in _PRINCIPAL_KEYS)
    if dropped:
        # A misspelled or unsupported key usually means a mis-wired
        # integration; say so rather than sealing a record with no principal.
        sys.stderr.write(
            "halo-record: principal key(s) dropped — %s not in human_id | "
            "creator_id | service_account | role_scope\n" % ", ".join(dropped))
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


VERIFICATION_STATUSES = {"allowed", "blocked", "modified", "unverified"}
OUTCOME_STATUSES = {"ok", "error", "denied"}
# Values the verifier accepts for authorization.decision and source.capture.
# build() drops anything else loudly rather than seal a record that can never
# verify (an append-only chain has no undo).
DECISIONS = {"allowed", "denied", "human_approved"}
CAPTURE_TIERS = {"captured", "ingested"}
_VERIFICATION_KEYS = ("verifier", "policy_ref", "checked_at")


def _norm_verification(verification):
    """Normalize an ingested verification claim into schema shape.

    The block is INGESTED from an upstream verification/policy gate — Halo
    seals what the gate said at the moment of the action, it does not
    adjudicate it. A block whose ``status`` is not one of the schema's enum
    values is dropped rather than sealed, so a malformed claim never poisons
    the chain; an absent block means no verification claim was made.
    """
    if not isinstance(verification, dict):
        return None
    if verification.get("status") not in VERIFICATION_STATUSES:
        # A supplied-but-invalid claim usually means the integration is
        # mis-wired; dropping it silently would hide that, so say so on stderr.
        sys.stderr.write(
            "halo-record: verification block dropped — status %r is not one "
            "of allowed | blocked | modified | unverified; the record seals "
            "with no verification claim\n" % (verification.get("status"),))
        return None
    out = {"status": verification["status"]}
    for k in _VERIFICATION_KEYS:
        if verification.get(k) not in (None, ""):
            out[k] = str(verification[k])
    return out


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


# The largest integer IEEE-754 float64 represents exactly (2**53 - 1). JSON
# readers that parse numbers into float64 (every browser, Node, and most JS
# tooling) silently round integers beyond this, so a record hashed over the
# exact literal would fail re-verification in those readers.
_MAX_EXACT_JSON_INT = 2**53 - 1


def _canon_safe(value, _depth=0, _active=None, render=True):
    """Recursively make a value safe for RFC 8785 canonicalization, which permits
    only integer-valued numbers. A non-integer float is preserved as a string
    instead of crashing the recorder when the record is hashed, and an integer
    whose magnitude exceeds ``_MAX_EXACT_JSON_INT`` is preserved as a string so
    every JSON reader recomputes the same canonical bytes the recorder hashed
    (float64-based parsers round larger integers, which would make an untampered
    chain fail self-verification). A no-op on any value that was already
    canonicalizable everywhere, so it never changes the hash of such records.
    Instrumentation must never take down the tool it is recording."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if -_MAX_EXACT_JSON_INT <= value <= _MAX_EXACT_JSON_INT:
            return value
        return int_text(value)
    if isinstance(value, float):
        if value.is_integer():
            as_int = int(value)
            if -_MAX_EXACT_JSON_INT <= as_int <= _MAX_EXACT_JSON_INT:
                return as_int
            return str(as_int)
        return str(value)
    if isinstance(value, str):
        return _no_lone_surrogates(value)
    if value is None or not render and not isinstance(value, (dict, list, tuple)):
        # ``render=False`` (the authority block) leaves a non-JSON value as is,
        # so it fails at seal instead of being stored as its text.
        return value
    if isinstance(value, (set, frozenset)):
        # Sets have no order or JSON form: a sorted list, as tool input renders them.
        value = sorted(value, key=sort_key)
    if not isinstance(value, (dict, list, tuple)):
        # Bytes and other objects are stored as the text they render as (and
        # masked like any other string before the record is sealed).
        return _no_lone_surrogates(str(value))
    if isinstance(value, (dict, list, tuple)):
        # A cycle or runaway nesting in caller data is marked, not recursed
        # into, so it can neither crash the recorder nor the host.
        if _depth >= MAX_DEPTH:
            return TOO_DEEP
        _active = _active if _active is not None else set()
        if id(value) in _active:
            return CIRCULAR
        _active.add(id(value))
        try:
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    # Keys become strings the way a JSON encoder writes them.
                    base = _no_lone_surrogates(json_key(k))
                    key = base
                    n = 2
                    while key in out:  # never let a normalized key overwrite another
                        key = "%s#%d" % (base, n)
                        n += 1
                    out[key] = _canon_safe(v, _depth + 1, _active, render)
                return out
            return [_canon_safe(v, _depth + 1, _active, render) for v in value]
        finally:
            _active.discard(id(value))
    return value


def _no_lone_surrogates(s):
    """Replace lone surrogates (no valid UTF-8 form) with U+FFFD so the stored
    record is what was hashed, in every implementation."""
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return "".join("\ufffd" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)
    return s


_PURPOSE_MAX = 500

# A stored summary is at most 200 characters, so the text it is redacted from is
# cut to a window first: masking work stays bounded however long a tool's
# response is. The cut lands on whitespace when it can, so a secret is not split
# into a fragment the patterns no longer recognize. Findings still scan the
# whole text.
_SUMMARY_WINDOW = 8192


def _summary_window(text):
    if len(text) <= _SUMMARY_WINDOW:
        return text
    cut = text[:_SUMMARY_WINDOW]
    ws = max(cut.rfind(" "), cut.rfind("\n"), cut.rfind("\t"))
    return cut[:ws] if ws > _SUMMARY_WINDOW // 2 else cut


def _norm_data(data):
    """Normalize the caller's ``data`` block so intuitive input can neither crash
    the recorder nor seal a schema-invalid record. The schema-typed keys are
    coerced (``region``/``purpose`` to string; ``cross_region`` to 0/1 from a
    bool or integer-valued number, dropped if it is not numeric so a stray
    ``"yes"`` never poisons the chain); every other key is made canon-safe."""
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        if k == "cross_region":
            if isinstance(v, bool):
                out[k] = int(v)
            elif isinstance(v, (int, float)) and v in (0, 1):
                out[k] = int(v)
            else:
                # Anything but a boolean or 0/1 is dropped, not sealed as
                # invalid — and said aloud, so a residency test never finds a
                # blank it cannot explain.
                import sys as _sys
                _sys.stderr.write(
                    "halo-record: data.cross_region=%r is not a boolean or 0/1; "
                    "dropped (the column will read as 'not declared')\n" % (v,))
        elif k in ("region", "purpose"):
            if v is None:
                continue  # absent, not the string "None"
            text = v if isinstance(v, str) else str(v)
            if k == "purpose":
                # Free text that is sealed and exported verbatim, so it gets the
                # same redaction as an input summary, with or without summaries.
                text = redact_text(text)[:_PURPOSE_MAX]
            out[k] = text
        else:
            out[k] = _canon_safe(v)
    return out


_OUTCOME_HASH_RE = re.compile(r"(?:sha256:)?[0-9a-fA-F]{16,64}")


def _sanitize_authority(authority):
    """Copy an authority block, masking any value that matches a named secret
    pattern (API keys, tokens, private-key blocks, connection strings, ...).
    The high-entropy catch-all is deliberately NOT applied: legitimate authority
    values are hashes and refs, which look exactly like entropy. Free-form text
    is not detected — the block's privacy remains a producer convention beyond
    these named formats (LIMITS section 6)."""
    def walk(v):
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                mk = mask_known_secrets(k) if isinstance(k, str) else k
                if mk != k:
                    print("halo-record: masked a known secret format used as an "
                          "authority KEY — keys should be names, never credentials",
                          file=sys.stderr)
                while mk in out:          # masked-key collision: keep both, distinctly
                    mk = mk + "~"
                out[mk] = walk(x)
            return out
        if isinstance(v, (list, tuple)):
            return [walk(x) for x in v]
        if isinstance(v, str):
            masked = mask_known_secrets(v)
            if masked != v:
                print("halo-record: masked a known secret format inside the "
                      "authority block — authority values should be hashes and "
                      "refs, never raw credentials", file=sys.stderr)
                return masked
        return v
    return walk(dict(authority))


def _authority_content_hash(authority):
    """Content identity of a full authority body (excluding the compaction
    marker), for guarding snapshot_id reuse."""
    body = {k: v for k, v in authority.items() if k != "same_as_previous"}
    return sha256_hex(canon(_canon_safe(body)))



def _as_str(field, value):
    """Coerce a scalar to str for a schema-typed string field; drop anything
    else with a stderr note. None passes through."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    sys.stderr.write("halo-record: %s=%r is not a string; dropped\n" % (field, value))
    return None


def _norm_caller_findings(findings):
    """Caller-supplied findings are sealed as given (LIMITS §13), but never in a
    shape the verifier rejects or the recorder cannot rank: entries must be
    mappings with a ``type``; a missing/unknown ``severity`` becomes INFO.
    A non-list is dropped (returns None so the recorder scans instead)."""
    if not isinstance(findings, list):
        sys.stderr.write(
            "halo-record: findings=%r is not a list; ignored, the recorder's own scan applies\n"
            % (findings,))
        return None
    out = []
    for f in findings:
        if not isinstance(f, dict) or not f.get("type"):
            sys.stderr.write("halo-record: finding %r lacks a type; dropped\n" % (f,))
            continue
        # Only the schema's three fields survive, and a caller-supplied sample
        # goes through the same masking as everything else the record stores.
        g = {"type": str(f["type"])}
        sev = f.get("severity")
        g["severity"] = sev if isinstance(sev, str) and sev in SEVERITY_RANK else "INFO"
        sample = f.get("sample")
        if isinstance(sample, (str, int, float, bool)):
            g["sample"] = redact_text(str(sample))[:120]
        out.append(g)
    return out

def build(action_type, category, tool=None, tool_input=None, *,
          session_id="local", agent=None, scope=None, decision=None,
          approver=None, findings=None, outcome=None, ts=None,
          subject=None, source=None, authority=None, summaries=True,
          principal=None, parent_id=None, threats=None, data=None,
          verification=None):
    """Construct a v0.1 record (without integrity.hash filled in).

    ``tool_input`` is hashed (canonical) and, by default, a redacted summary is
    stored; argument text enters the record only through that summary (at most
    200 characters; a short input that matches no pattern appears as written,
    and ``summaries=False`` stores none). If ``findings`` is None, the input,
    the outcome, and caller-defined outcome and ``data`` fields are scanned
    automatically.

    ``subject`` (a str id or ``{"id", "name"}`` dict) tags the record with the
    tenant/customer it belongs to — the segmentation key. ``authority`` may carry
    a privacy-safe snapshot of the rules/tooling context that governed the run
    (hashes and refs, not raw prompts or private policy text; known secret
    formats are masked at seal time, free-form text is not detected). ``summaries=False``
    drops every human-readable summary, every finding excerpt, and any custom
    ``outcome`` keys (only the schema's non-text outcome fields survive),
    leaving hashes plus finding types/severities. The ``authority`` block is
    still stored (after known-secret masking) — keep it to hashes and refs if
    the record must stay hash-only.

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
    is not comprehensive PII coverage — see LIMITS.md. ``verification`` records
    what an upstream verification/policy gate said about this action at the
    moment it ran (``status`` of allowed | blocked | modified | unverified,
    plus optional ``verifier`` / ``policy_ref`` / ``checked_at``) — sealed
    as supplied, the reporting layer's claim, never adjudicated by Halo; an
    absent block means no verification claim was made. ``outcome["status"]``,
    when present, must be ``ok``, ``error`` or ``denied``; any other value
    raises ValueError before anything is sealed.
    """
    if action_type not in ACTION_TYPES:
        raise ValueError("action.type must be one of %s" % sorted(ACTION_TYPES))
    if category not in CATEGORIES:
        raise ValueError("action.category must be one of %s" % sorted(CATEGORIES))
    if isinstance(outcome, dict) and "status" in outcome and (
            not isinstance(outcome["status"], str) or outcome["status"] not in OUTCOME_STATUSES):
        # The verifier rejects any other value, and an append-only chain has
        # no undo: refuse it here, before anything is sealed.
        raise ValueError("outcome.status must be one of %s, not %r"
                         % (sorted(OUTCOME_STATUSES), outcome["status"]))

    # Schema-typed string fields: a scalar is coerced to str; anything else is
    # dropped with a note rather than sealed into a record that can never
    # verify (an append-only chain has no undo).
    tool = _as_str("tool", tool)
    scope = _as_str("authorization.scope", scope)
    approver = _as_str("authorization.approver", approver)
    session_id = _as_str("session_id", session_id) or "local"
    if isinstance(agent, str):
        agent = {"id": agent, "name": agent}
    elif isinstance(agent, dict):
        agent = dict(agent)
        for k in ("id", "name", "version", "model", "model_version"):
            v = agent.get(k)
            if v is None or isinstance(v, str):
                continue
            if isinstance(v, (int, float, bool)):
                agent[k] = str(v)
            else:
                sys.stderr.write("halo-record: agent.%s=%r is not a scalar; recorded as unknown\n" % (k, v))
                agent = None
                break
    elif agent is not None:
        sys.stderr.write("halo-record: agent=%r is not a mapping; recorded as unknown\n" % (agent,))
        agent = None
    if findings is not None:
        findings = _norm_caller_findings(findings)

    action = {"type": action_type, "category": category}
    if tool is not None:
        action["tool"] = tool
    if decision is not None and (not isinstance(decision, str) or decision not in DECISIONS):
        # Same discipline as verification.status: the verifier rejects any
        # other value, so an integration typo must not seal a chain that can
        # never verify. Drop the decision loudly; scope/approver still seal.
        sys.stderr.write(
            "halo-record: authorization.decision=%r is not one of %s; dropped\n"
            % (decision, sorted(DECISIONS)))
        decision = None
    # The authorization block appears only when the integration supplies one.
    # Nothing is defaulted: a record with no decision says "no gate reported",
    # never "allowed".
    if scope is not None or decision is not None or approver is not None:
        auth = {}
        if decision is not None:
            auth["decision"] = decision
        if scope is not None:
            auth["scope"] = scope
        if approver is not None:
            auth["approver"] = approver
        elif decision == "human_approved":
            # Sealed as supplied, but an approval with no approver is the
            # exception an approval-control test will flag — say so now.
            print("halo-record: decision is human_approved but no approver was "
                  "supplied; the record seals without one", file=sys.stderr)
        action["authorization"] = auth
    if tool_input is not None:
        inp = {"hash": input_hash(tool_input)}
        if summaries:
            # Leaves the field redactor does not treat as text (numbers, sets,
            # bytes, object reprs, credential-bearing URL paths) are caught by a
            # final pass over the rendered summary.
            inp["summary"] = mask_known_secrets(
                _summary_window(str(redact_fields(tool_input))))[:200]
        action["input"] = inp

    # Normalize the outcome up front so its summary is redacted before it is
    # sealed/served and so it can be scanned for secrets alongside the input.
    outcome_summary_raw = None
    outcome_scan = None
    outcome_custom = None
    if outcome is not None:
        outcome = dict(outcome)
        outcome_scan = outcome.pop("_scan", None)
        outcome = _canon_safe(outcome)
        # Caller-defined outcome keys are scanned like the rest of the record.
        outcome_custom = {k: v for k, v in outcome.items()
                          if k not in ("status", "summary", "hash")} or None
        if "summary" in outcome and outcome["summary"] is not None:
            outcome_summary_raw = str(outcome["summary"])
        if not summaries:
            # Hash-only records keep only the schema's non-text outcome fields —
            # and only when their values have the schema's shape, so payload text
            # cannot ride into a hash-only record under those key names.
            kept = {}
            if outcome.get("status") in ("ok", "error", "denied"):
                kept["status"] = outcome["status"]
            h = outcome.get("hash")
            if isinstance(h, str) and _OUTCOME_HASH_RE.fullmatch(h):
                kept["hash"] = h
            outcome = kept
        else:
            if outcome_summary_raw is not None:
                outcome["summary"] = redact_text(_summary_window(outcome_summary_raw))[:200]
            h = outcome.get("hash")
            if h is not None and not (isinstance(h, str) and _OUTCOME_HASH_RE.fullmatch(h)):
                outcome.pop("hash")  # only a hash-shaped value is kept under that name

    if findings is None:
        findings = []
        seen = set()
        if tool_input is not None:
            findings += scan_fields(tool_input, _seen=seen)
        if outcome_scan is not None:
            findings += scan_fields(outcome_scan, _seen=seen)
        elif outcome_summary_raw is not None:
            findings += scan(outcome_summary_raw)
        if outcome_custom is not None:
            findings += scan_fields(outcome_custom, _seen=seen)
        if isinstance(data, dict):
            data_custom = {k: v for k, v in data.items() if k not in ("pii_types", "cross_region")}
            if data_custom:
                findings += scan_fields(_canon_safe(data_custom), _seen=seen)
    findings = findings or []
    if not summaries:
        # Hash-only records carry finding types and severities, never excerpts.
        # Non-mapping entries pass through untouched and fail (or not) exactly
        # where they always did.
        findings = [({k: v for k, v in f.items() if k != "sample"}
                     if isinstance(f, dict) else f) for f in findings]

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": str(uuid.uuid4()),
        "session_id": session_id,
        "ts": _valid_ts(ts),
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
        record["authority"] = _sanitize_authority(_canon_safe(authority, render=False))
    threats = _norm_threats(threats)
    if threats is not None:
        record["threats"] = threats
    verification = _norm_verification(verification)
    if verification is not None:
        record["verification"] = verification
    # data.pii_types is derived from the scanner's personal-data findings and
    # merged with any caller-supplied request-context (region/purpose/...).
    data_block = _norm_data(data)
    pii_types = _pii_types_from_findings(findings)
    if pii_types is not None:
        data_block["pii_types"] = pii_types
    if data_block:
        record["data"] = data_block
    if outcome is not None:
        record["outcome"] = outcome
    _scrub_fields(record)
    if not summaries:
        _pseudonymize_ids(record)
    # Final guard: a caller-supplied value (a float score in data/outcome, say)
    # must never crash the recorder when the record is hashed. No-op on a record
    # that was already canonicalizable, so the hash of valid records is unchanged.
    return {k: _canon_safe(v, render=(k != "authority")) for k, v in record.items()}


# Fields the recorder itself produces or has already redacted; everything else
# a caller can set is scrubbed before sealing.
_SCRUB_SKIP = {"schema_version", "record_id", "ts", "integrity",
               "authority", "severity"}
# Fields that name a person or account: credentials are masked, but the email or
# phone the field exists to carry is kept (an approver must stay identifiable).
_IDENTITY_PATHS = {("action", "authorization", "approver"), ("subject", "name")}


_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")


def _valid_ts(ts):
    """A caller-supplied timestamp is kept only if it is RFC 3339; anything else
    is replaced with the current time (and said aloud) rather than sealed."""
    if ts is None:
        return _now()
    if isinstance(ts, str) and _TS_RE.fullmatch(ts):
        return ts
    import sys as _sys
    _sys.stderr.write("halo-record: ts is not an RFC 3339 timestamp; recorded the current time\n")
    return _now()


def _scrub_fields(record):
    def walk(node, path):
        if isinstance(node, dict):
            out = {}
            for k in list(node):
                p = path + (k,)
                if (not path and k in _SCRUB_SKIP) or p in (
                        ("subject", "id"), ("data", "pii_types"), ("data", "purpose"),
                        ("action", "input"), ("outcome", "summary"), ("outcome", "hash"),
                        ("action", "type"), ("action", "category")):
                    out[k] = node[k]
                    continue
                # Caller-chosen key names are scrubbed too; a collision keeps both.
                key = k if not path or not isinstance(k, str) else mask_known_secrets(k)
                n = 2
                while key in out:
                    key = "%s#%d" % (mask_known_secrets(k), n)
                    n += 1
                if credential_value(k, node[k]):
                    out[key] = CREDENTIAL_MASK  # a credential-named field, masked whole
                elif isinstance(node[k], list):
                    out[key] = [CREDENTIAL_MASK if credential_value(k, el) else walk(el, p)
                                for el in node[k]]
                else:
                    out[key] = walk(node[k], p)
            return out
        if isinstance(node, list):
            return [walk(v, path) for v in node]
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            return _scrub_number(node)
        if isinstance(node, str):
            if path and path[-1] in _ID_NAMES and _OPAQUE_ID.fullmatch(node):
                return node  # a UUID or hex id carries no secret; patterns can misfire on it
            if path in _IDENTITY_PATHS or (path and path[0] == "principal"):
                return mask_secrets_only(node)
            return mask_known_secrets(node) if _identifier_like(path) else redact_text(node)
        return node
    scrubbed = walk(record, ())
    record.clear()
    record.update(scrubbed)


def _scrub_number(n):
    """A number whose digits form a named identifier (a card number given as a
    JSON number) is stored as its mask; any other number is kept as is."""
    if isinstance(n, float):
        if not n.is_integer():
            return n
        text = str(int(n))
    else:
        text = str(n)
    if len(text.lstrip("-")) < 13:
        return n
    masked = mask_known_secrets(text)
    return masked if masked != text else n


def _pseudonymize_ids(record):
    """Hash-only records keep ids for grouping and links but never store a
    secret-shaped token in one: each is replaced by a stable digest. The
    subject id is left as is: it routes the record to its tenant's chain."""
    def walk(node, path):
        if isinstance(node, dict):
            return {k: (node[k] if (not path and k in _SCRUB_SKIP) or path + (k,) == ("subject", "id")
                        else walk(node[k], path + (k,))) for k in node}
        if isinstance(node, list):
            return [walk(v, path) for v in node]
        if isinstance(node, str) and path and _identifier_like(path):
            if path[-1] in _ID_NAMES and _OPAQUE_ID.fullmatch(node):
                return node
            return pseudonymize_secrets(node)
        return node
    scrubbed = walk(record, ())
    record.clear()
    record.update(scrubbed)


_ID_NAMES = {"id", "session_id", "parent_id", "record_id", "snapshot_id", "ref", "policy_ref"}
_OPAQUE_ID = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|[0-9A-Fa-f]{16,64}")


def _identifier_like(path):
    """Identifier-shaped fields (ids, versions, refs) skip the high-entropy
    catch-all, which would mangle legitimate opaque identifiers."""
    return path[-1] in ("id", "session_id", "parent_id", "version", "ref", "policy_ref") or \
        path[:1] in (("agent",), ("threats",))


def _complete_record(line):
    """The record on ``line`` if it is a complete sealed record, else None."""
    try:
        rec = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(rec, dict):
        return None
    integ = rec.get("integrity")
    if not isinstance(integ, dict) or not isinstance(integ.get("hash"), str) or not integ["hash"]:
        return None
    return rec


def _tail_state(path):
    """``(record, incomplete, has_content)`` for the chain file at ``path``:
    the last complete record (or None), how many non-empty lines after it are
    not complete records (a torn write or a truncation), and whether the file
    holds anything but whitespace. Reads the tail window, and the whole file
    only when the window holds no complete record."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            back = min(size, 262144)
            fh.seek(size - back)
            buf = fh.read(back)
    except OSError:
        return None, 0, False
    lines = buf.split(b"\n")
    if back < size:
        lines = lines[1:]  # the first line in the window may be cut
    incomplete = 0
    for line in reversed(lines):
        if not line.strip():
            continue
        rec = _complete_record(line)
        if rec is not None:
            return rec, incomplete, True
        incomplete += 1
    if back < size:
        last, incomplete = None, 0
        with open(path, "rb") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = _complete_record(line)
                if rec is not None:
                    last, incomplete = rec, 0
                else:
                    incomplete += 1
        return last, incomplete, True
    return None, incomplete, incomplete > 0


def _ends_with_newline(path):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                return True
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) == b"\n"
    except OSError:
        return True


class Recorder:
    """Append-only writer that maintains the hash chain in a JSONL file.

    Appends are serialized both within a process (threading.Lock — agents call
    tools in parallel) and across processes (an ``fcntl`` lock on a ``.lock``
    sidecar file, POSIX) — hook-style capture spawns one short-lived process
    per tool call, and two of those appending at once must not both extend the
    same chain head. The head is cached per instance and re-read from disk
    whenever the file has grown underneath the cache.
    """

    def __init__(self, path, *, expected_subjects=None):
        self.path = os.path.expanduser(path)
        # When set (TenantRecorder does), each append re-checks under the file
        # lock that the chain's last record belongs to one of these subjects, so
        # two writers that opened the same file cannot interleave tenants.
        self._expected_subjects = (set(expected_subjects)
                                   if expected_subjects is not None else None)
        self._lock = threading.Lock()
        self._last_hash = None
        self._last_record_id = None
        self._last_authority_snapshot_id = None
        self._last_authority_hash = None
        self._tail_loaded = False
        self._last_size = None

    def _acquire_flock(self):
        if fcntl is None:
            return None
        try:
            fh = open(self.path + ".lock", "ab")
        except OSError as e:
            raise OSError(
                e.errno,
                "cannot open chain for append (lock sidecar %s.lock): %s"
                % (self.path, e.strerror)) from e
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
        """Read the chain head (and last authority snapshot) from disk.

        The head is the last COMPLETE record. Lines after it that are not
        complete records (a torn write, a truncated file) are left in place,
        reported on stderr, and skipped: the next record links to the last
        complete one and starts on a new line, so the chain never restarts at
        genesis on top of earlier records and no bytes are lost or hidden —
        ``halo verify`` reports the incomplete line. A file with no complete
        record at all keeps its bytes too; the chain starts after them."""
        rec, incomplete, _ = (_tail_state(self.path) if os.path.exists(self.path)
                              else (None, 0, False))
        if incomplete:
            sys.stderr.write(
                "halo-record: %d line(s) at the end of %s are not a complete record "
                "(a torn write or a truncation); they are kept in place, the next "
                "record %s, and `halo verify` will report them\n"
                % (incomplete, self.path,
                   "links to the last complete record" if rec is not None
                   else "starts the chain after them"))
        self._last_hash = GENESIS_PREV
        self._last_record_id = None
        self._last_authority_snapshot_id = None
        # The last full authority body's content hash, when the tail carries one.
        # A compacted tail (same_as_previous) leaves this None: the previous full
        # body is further back than the one-line tail read, so across a process
        # restart the snapshot_id is trusted — the reuse guard is strongest where
        # the hazard lives, inside a single producing process.
        self._last_authority_hash = None
        if rec is not None:
            self._last_hash = rec["integrity"]["hash"]
            self._last_record_id = rec.get("record_id")
            authority = rec.get("authority")
            if isinstance(authority, dict):
                self._last_authority_snapshot_id = authority.get("snapshot_id")
                if not authority.get("same_as_previous"):
                    try:
                        self._last_authority_hash = _authority_content_hash(authority)
                    except Exception:
                        self._last_authority_hash = None
        self._last_size = self._size()
        self._tail_loaded = True

    def _current_tail(self):
        """Chain head + authority snapshot id, re-reading from disk if another
        process has appended since this instance last looked."""
        if not self._tail_loaded or self._size() != self._last_size:
            self._refresh_tail()
        return (self._last_hash, self._last_authority_snapshot_id,
                self._last_authority_hash)

    def last_hash(self):
        with self._lock:
            return self._current_tail()[0]

    def last_record_id(self):
        """``record_id`` of the most recent record in the chain, or ``None`` on
        an empty chain. Pass it as ``parent_id`` on the next record to link a
        delegated action to the action that spawned it."""
        with self._lock:
            self._current_tail()
            return self._last_record_id

    def last_authority_snapshot_id(self):
        with self._lock:
            return self._current_tail()[1]

    @staticmethod
    def _dedupe_authority(record, previous_snapshot_id, previous_authority_hash):
        """Compact a repeated authority block — but only when the CONTENT also
        matches the previous full snapshot. A reused snapshot_id over changed
        authority state is stored in full (and said loudly): silently collapsing
        it would misattribute the run to rules that were no longer in effect."""
        authority = record.get("authority")
        if not isinstance(authority, dict):
            return None, None
        snapshot_id = authority.get("snapshot_id")
        content_hash = _authority_content_hash(authority)
        if snapshot_id and snapshot_id == previous_snapshot_id:
            if content_hash == previous_authority_hash:
                record["authority"] = {
                    "snapshot_id": snapshot_id,
                    "same_as_previous": True,
                }
                return snapshot_id, previous_authority_hash
            if previous_authority_hash is None:
                # Fresh process over a compacted tail: the previous full body is
                # unknown, so store this one in full rather than trust the id.
                return snapshot_id, content_hash
            print("halo-record: authority snapshot_id %r reused with changed "
                  "content — storing the full snapshot; a snapshot_id must stay "
                  "stable only while the underlying authority is unchanged"
                  % snapshot_id, file=sys.stderr)
        return snapshot_id, content_hash

    def _check_tail_subject(self):
        rec = _tail_state(self.path)[0]
        if rec is None:
            return
        subj = rec.get("subject")
        sid = (subj.get("id") or None) if isinstance(subj, dict) else None
        if sid not in self._expected_subjects:
            raise ValueError("halo-record: %s holds records for another subject; "
                             "refusing to mix tenants in one chain" % self.path)

    def append(self, record):
        with self._lock:
            flock = self._acquire_flock()
            try:
                if self._expected_subjects is not None:
                    self._check_tail_subject()
                prev, prev_snapshot_id, prev_authority_hash = self._current_tail()
                authority_snapshot_id, authority_hash = self._dedupe_authority(
                    record, prev_snapshot_id, prev_authority_hash)
                record.setdefault("integrity", {})
                record["integrity"]["prev_hash"] = prev
                record["integrity"]["hash"] = compute_hash(record, prev)
                # A last line without its newline (torn, or written by another
                # tool) is ended first, so the new record never joins it.
                lead = "" if _ends_with_newline(self.path) else "\n"
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(lead + json.dumps(record, separators=(",", ":")) + "\n")
                    fh.flush()
                    self._last_size = fh.tell()
                self._last_hash = record["integrity"]["hash"]
                self._last_record_id = record.get("record_id")
                self._last_authority_snapshot_id = authority_snapshot_id
                self._last_authority_hash = authority_hash
            finally:
                self._release_flock(flock)
        return record


# File-name budget: 255 bytes less the ".jsonl.lock" sidecar suffix. Cleaned
# names are ASCII, so characters are bytes.
_NAME_MAX = 255 - len(".jsonl.lock")
_NAME_CUT = 128

_ASCII_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


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
        """Filename cleaning used before 0.2.46; kept to find existing chains."""
        cleaned = "".join(
            c if (c.isalnum() or c in "-_.") else "_" for c in str(name)
        ).strip("._")
        return cleaned or "tenant"

    @staticmethod
    def _safe_ascii(name):
        cleaned = "".join(
            c if (c in _ASCII_NAME_CHARS) else "_" for c in str(name)
        ).strip("._")
        return cleaned or "tenant"

    def _subject_id(self, record):
        subj = record.get("subject")
        if isinstance(subj, dict) and subj.get("id"):
            return subj["id"]
        return self.default

    def path_for(self, subject_id):
        """One file per distinct subject ID. An ID that is already filename-safe
        keeps its plain name (``acme-corp.jsonl``); an ID the cleaning step would
        alter gets a ``~`` plus a digest of the original ID, so two different IDs
        can never share a file (``acme/a`` and ``acme_a`` stay apart). ``~`` is
        never produced by cleaning, so a plain name cannot imitate a digested one."""
        raw = str(subject_id)
        safe = self._safe_ascii(raw)
        # The default (subjectless) chain keeps its established name; a real
        # subject that cleans to the same name is refused by the mixed-file check.
        # Uppercase also takes a digest: case-insensitive filesystems (macOS,
        # Windows) would otherwise store "ACME" and "acme" in one file.
        if (safe != raw or raw != raw.lower()) and subject_id != self.default:
            safe = self._digested(raw)
        elif len(safe) > _NAME_MAX:
            safe = self._digested(raw)
        return os.path.join(self.directory, safe + ".jsonl")

    @classmethod
    def _digested(cls, raw):
        """``<cleaned>~<digest>``; a long cleaned name is cut so the file name
        (with its ``.jsonl.lock`` sidecar) fits a 255-byte file-name limit. The
        digest of the full id keeps two long ids that share a prefix apart.
        Names that already fit are unchanged."""
        safe = cls._safe_ascii(raw)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        if len(safe) + 1 + len(digest) > _NAME_MAX:
            safe = safe[:_NAME_CUT]
        return "%s~%s" % (safe, digest)

    def chain_path_for(self, subject_id):
        """The file this recorder actually appends to for ``subject_id`` — the
        nominal ``path_for`` name, a reused legacy file, or a digested fallback
        when the nominal file already holds other subjects."""
        return self.recorder_for(subject_id).path

    @staticmethod
    def _file_subjects(path):
        """Subject IDs already present in a chain file (``None`` for subjectless)."""
        found = set()
        if not os.path.exists(path):
            return found
        # Split the way the verifier does (verify.read_log_lines): on "\n"
        # only, a CR kept as JSON whitespace, a leading BOM skipped.
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for line in fh.read().split("\n"):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                subj = rec.get("subject")
                sid = subj.get("id") if isinstance(subj, dict) else None
                if not sid:
                    sid = None  # same truthiness rule as _subject_id: falsy = default
                elif not isinstance(sid, (str, int, float, bool)):
                    sid = json.dumps(sid, sort_keys=True)
                found.add(sid)
        return found

    def recorder_for(self, subject_id):
        if subject_id not in self._recorders:
            if not os.path.isdir(self.directory):
                os.makedirs(self.directory, exist_ok=True)
            path = self.path_for(subject_id)
            expected = {subject_id} | ({None} if subject_id == self.default else set())
            # Continuity for chains written before digested names: if the plain
            # file exists and holds only this subject, keep appending there.
            legacy = os.path.join(self.directory, self._safe(subject_id) + ".jsonl")
            if legacy != path and not os.path.exists(path) and os.path.exists(legacy):
                legacy_subjects = self._file_subjects(legacy)
                if legacy_subjects and legacy_subjects <= expected:
                    path = legacy
                elif subject_id in legacy_subjects:
                    # This subject's earlier records share a file with other
                    # subjects, so they cannot be continued without mixing
                    # tenants. Say where they are and where the new chain is.
                    sys.stderr.write(
                        "halo-record: earlier records for %r are in %s together with "
                        "other subjects; new records for %r start their own chain in "
                        "%s (the earlier records stay where they are)\n"
                        % (subject_id, legacy, subject_id, path))
            others = self._file_subjects(path) - expected
            if others:
                # A file written by an earlier version can hold several subjects.
                # Continue this subject in its own digested chain rather than
                # raise into the agent, and say so.
                raw = str(subject_id)
                alt = os.path.join(self.directory, self._digested(raw) + ".jsonl")
                if self._file_subjects(alt) - expected:
                    raise ValueError("halo-record: %s and %s both hold records for other "
                                     "subjects; refusing to mix tenants" % (path, alt))
                sys.stderr.write("halo-record: %s also holds other subjects; recording %r in %s\n"
                                 % (path, raw, alt))
                path = alt
            self._recorders[subject_id] = Recorder(path, expected_subjects=expected)
        return self._recorders[subject_id]

    def _explicit_default_recorder(self, subject_id):
        """A record whose subject id equals the default chain's name is a real
        tenant, not a subjectless record: it gets its own digested chain so it
        never shares the subjectless chain."""
        key = ("subject", subject_id)
        if key not in self._recorders:
            if not os.path.isdir(self.directory):
                os.makedirs(self.directory, exist_ok=True)
            path = os.path.join(self.directory, self._digested(str(subject_id)) + ".jsonl")
            if self._file_subjects(path) - {subject_id}:
                raise ValueError("halo-record: %s holds records for other subjects; "
                                 "refusing to mix tenants" % path)
            self._recorders[key] = Recorder(path, expected_subjects={subject_id})
        return self._recorders[key]

    def append(self, record):
        subj = record.get("subject")
        if isinstance(subj, dict) and subj.get("id") and subj["id"] == self.default:
            return self._explicit_default_recorder(subj["id"]).append(record)
        return self.recorder_for(self._subject_id(record)).append(record)
