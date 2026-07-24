"""Date-bounded, workpaper-ready evidence export.

Auditors collect evidence over an audit period, in formats that drop into
working papers: flat files, one row per event, dated. ``halo export`` turns a
chain (or a window of it) into exactly that — a CSV of one row per record —
plus a small JSON manifest that ties the export back to the verifiable chain
it came from (chain head hash, record counts, window bounds) and to the CSV
itself (the file's SHA-256).

The CSV is a review surface, not the evidence itself: full fidelity stays in
the chain. The manifest's head hash links the export to its source chain, and
its ``csv_sha256`` links it to the exact file bytes — a CSV edited after
export no longer matches its manifest. The export refuses to run on a chain
that fails verification — an evidence file should never outlive the integrity
of its source.

Dates are inclusive: ``--from 2026-06-01 --to 2026-06-30`` covers the whole
of June 30. Timestamps are compared in UTC.

Rows carry the agent build and model that produced them (``agent_version``,
``model``, ``model_version``) whenever the chain recorded those fields — an
audit answer is only as strong as its binding to the version that was
actually running during the window.
"""

import ast
import csv
import datetime
import hashlib
import json
import os

from .verify import verify_log

# Grouped so a reviewer reading left to right gets: when → what happened →
# who did it → under what authority → what was flagged → where it came from →
# how to verify it. The plain-language columns (action_summary, outcome_summary)
# sit next to the machine fields deliberately: an assessor scanning the sheet
# should be able to tell what an action DID without opening the JSONL.
CSV_COLUMNS = [
    # when
    "ts",
    # what happened
    "action_type",
    "category",
    "tool",
    "action_summary",
    "outcome",
    "outcome_summary",
    # who
    "subject",
    "subject_name",
    "principal",
    "agent",
    "agent_version",
    "model",
    "model_version",
    # under what authority
    "decision",
    "scope",
    "authority_snapshot",
    # what was flagged
    "severity",
    "findings",
    "threats",
    "pii_types",
    # provenance
    "source",
    "session_id",
    # identity + verification
    "record_id",
    "parent_id",
    "prev_hash",
    "hash",
]


def _parse_ts(value):
    """Parse an RFC 3339 timestamp (tolerating a trailing Z) to an aware UTC datetime."""
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def parse_bound(value, *, end=False):
    """Parse a --from/--to bound. Date-only values cover the whole day:
    a ``--to`` date extends to the last microsecond of that day (inclusive)."""
    if value is None:
        return None
    text = str(value).strip()
    if len(text) == 10:  # YYYY-MM-DD
        day = datetime.date.fromisoformat(text)
        t = datetime.time.max if end else datetime.time.min
        return datetime.datetime.combine(day, t, tzinfo=datetime.timezone.utc)
    parsed = _parse_ts(text)
    if parsed is None:
        raise ValueError(f"unrecognized date/time: {value!r}")
    return parsed


def load_records(path):
    records = []
    with open(os.path.expanduser(path), "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                records.append(json.loads(line))
    return records


def in_window(record, start=None, end=None):
    ts = _parse_ts(record.get("ts"))
    if ts is None:
        return False
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


def _readable(value):
    """Render a summary field as something a person reads in a spreadsheet.

    Summaries are redacted at capture but arrive in whatever shape the adapter
    wrote — a string, or a small mapping of the call's arguments. A raw dict
    repr (``{'ticket': 'T-8841'}``) is noise in a review sheet, so mappings are
    flattened to ``key=value; key=value`` and sequences joined, matching how
    the principal column already reads."""
    if value is None:
        return ""
    if isinstance(value, str):
        # The recorder stores a redacted summary of the call's arguments, and
        # for structured inputs that lands as the *string form* of a mapping
        # ("{'to': 'a****@acme.com'}"). Readable in JSON, noise in a review
        # sheet — so re-render it. literal_eval only evaluates literals (no
        # code execution), and anything that isn't one is returned untouched.
        stripped = value.strip()
        if stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]"):
            try:
                return _readable(ast.literal_eval(stripped))
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                return value
        return value
    if isinstance(value, dict):
        return "; ".join("%s=%s" % (k, _readable(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "; ".join(_readable(v) for v in value)
    return str(value)


def matches_tools(record, tools=None):
    """Whether a record's tool is in ``tools`` (case-insensitive, exact match).

    ``None`` or an empty selection means "no tool filter" — every record passes.
    Scoping an export to specific tools is how an assessor pulls just the
    actions a control covers (e.g. only the email or database calls) without
    hand-filtering the sheet afterward."""
    if not tools:
        return True
    tool = ((record.get("action") or {}).get("tool") or "").lower()
    return tool in {t.strip().lower() for t in tools if t and t.strip()}


def _neutralize(value):
    """Defuse spreadsheet formula injection in a CSV cell.

    The export's target flow is "open in Excel/Sheets or upload to a GRC
    platform", and record fields (tool names, session ids, summaries) can be
    influenced by whatever the agent touched. A cell starting with ``=``,
    ``+``, ``-``, ``@``, tab, or CR would execute as a formula there, so those
    cells are prefixed with a single quote — the standard neutralization,
    displayed by spreadsheets as plain text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _row(record):
    action = record.get("action") or {}
    authority = record.get("authority") or {}
    subject = record.get("subject") or {}
    principal = record.get("principal") or {}
    agent = record.get("agent") or {}
    findings = record.get("findings") or []
    threats = record.get("threats") or []
    data = record.get("data") or {}
    row = {
        "ts": record.get("ts", ""),
        "record_id": record.get("record_id", ""),
        "parent_id": record.get("parent_id", ""),
        "session_id": record.get("session_id", ""),
        "subject": subject.get("id", ""),
        "subject_name": subject.get("name", ""),
        "principal": "; ".join("%s=%s" % (k, principal[k]) for k in
                               ("human_id", "creator_id", "service_account", "role_scope")
                               if principal.get(k)),
        "agent": agent.get("name") or agent.get("id", ""),
        "agent_version": agent.get("version", ""),
        "model": agent.get("model", ""),
        "model_version": agent.get("model_version", ""),
        "action_type": action.get("type", ""),
        "category": action.get("category", ""),
        "tool": action.get("tool", ""),
        # The redacted, human-readable description of the call and its result.
        # Raw arguments are never exported — only the scrubbed summary the
        # recorder already wrote (see LIMITS.md §6 on redaction bounds).
        "action_summary": _readable((action.get("input") or {}).get("summary")),
        "outcome_summary": _readable((record.get("outcome") or {}).get("summary")),
        "decision": (action.get("authorization") or {}).get("decision", ""),
        "scope": (action.get("authorization") or {}).get("scope", ""),
        "prev_hash": (record.get("integrity") or {}).get("prev_hash", ""),
        "severity": record.get("severity", ""),
        "findings": "; ".join(
            f.get("type", "") for f in findings if isinstance(f, dict)
        ),
        "threats": "; ".join(
            t.get("type", "") for t in threats if isinstance(t, dict)
        ),
        "pii_types": "; ".join(data.get("pii_types") or []),
        "outcome": (record.get("outcome") or {}).get("status", ""),
        "source": (
            "%s:%s" % ((record.get("source") or {}).get("capture", ""),
                       (record.get("source") or {}).get("adapter", ""))
            if isinstance(record.get("source"), dict)
            else (record.get("source") or "")
        ),
        "authority_snapshot": authority.get("snapshot_id", ""),
        "hash": (record.get("integrity") or {}).get("hash", ""),
    }
    return {k: _neutralize(v) for k, v in row.items()}


def build_manifest(records, window_records, *, source_log, start=None, end=None,
                   verified=None, csv_sha256=None, tools=None):
    def _iso(dt):
        return dt.isoformat() if dt else None

    manifest = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_log": os.path.basename(str(source_log)),
        "window": {"from": _iso(start), "to": _iso(end)},
        # A tool filter narrows the exported population, so it is disclosed
        # here: a reviewer must be able to see that this CSV is a SUBSET and
        # exactly how it was scoped, never a silent selection.
        "tool_filter": sorted({t.strip() for t in tools if t and t.strip()}) if tools else None,
        "window_records": len(window_records),
        # SHA-256 of the exported CSV file's bytes: ties the manifest to the
        # exact evidence file it describes, so a CSV edited after export no
        # longer matches its manifest.
        "csv_sha256": csv_sha256,
        "chain": {
            "total_records": len(records),
            "head_hash": (records[-1].get("integrity") or {}).get("hash", "")
            if records
            else None,
            "verified": verified,
            # what "verified" attests: the chain is intact relative to its own
            # head (integrity). It is NOT a completeness claim — records dropped
            # from the tail need an external witness (see LIMITS.md).
            "verified_scope": "integrity_relative_to_head",
        },
    }
    if window_records:
        manifest["window"]["first_ts"] = window_records[0].get("ts")
        manifest["window"]["last_ts"] = window_records[-1].get("ts")
        manifest["window"]["first_record_id"] = window_records[0].get("record_id")
        manifest["window"]["last_record_id"] = window_records[-1].get("record_id")
    return manifest


def export(log_path, out_path, *, start=None, end=None, tools=None,
           manifest_path=None, out=print):
    """Verify the chain, then write the windowed CSV + manifest.

    Returns 0 on success, 1 if the chain fails verification (nothing is
    written in that case: no evidence file from a broken chain)."""
    silent = lambda *a, **k: None  # noqa: E731
    if not verify_log(log_path, out=silent):
        out(f"REFUSED: {log_path} fails verification; no export written.")
        return 1
    records = load_records(log_path)
    window = [r for r in records
              if in_window(r, start, end) and matches_tools(r, tools)]
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for record in window:
            writer.writerow(_row(record))
    with open(out_path, "rb") as fh:
        csv_sha256 = hashlib.sha256(fh.read()).hexdigest()
    manifest = build_manifest(
        records, window, source_log=log_path, start=start, end=end, verified=True,
        csv_sha256=csv_sha256, tools=tools,
    )
    m_path = manifest_path or (str(out_path) + ".manifest.json")
    with open(m_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    out(
        f"exported {len(window)} of {len(records)} records -> {out_path} "
        f"(manifest: {m_path}; chain head {manifest['chain']['head_hash'][:16]}...)"
    )
    return 0
