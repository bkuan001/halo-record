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

import csv
import datetime
import hashlib
import json
import os

from .verify import verify_log

CSV_COLUMNS = [
    "ts",
    "record_id",
    "parent_id",
    "session_id",
    "subject",
    "principal",
    "agent",
    "agent_version",
    "model",
    "model_version",
    "action_type",
    "category",
    "tool",
    "decision",
    "severity",
    "findings",
    "threats",
    "pii_types",
    "outcome",
    "source",
    "authority_snapshot",
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
        "decision": (action.get("authorization") or {}).get("decision", ""),
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
                   verified=None, csv_sha256=None):
    def _iso(dt):
        return dt.isoformat() if dt else None

    manifest = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_log": os.path.basename(str(source_log)),
        "window": {"from": _iso(start), "to": _iso(end)},
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
        },
    }
    if window_records:
        manifest["window"]["first_ts"] = window_records[0].get("ts")
        manifest["window"]["last_ts"] = window_records[-1].get("ts")
        manifest["window"]["first_record_id"] = window_records[0].get("record_id")
        manifest["window"]["last_record_id"] = window_records[-1].get("record_id")
    return manifest


def export(log_path, out_path, *, start=None, end=None, manifest_path=None, out=print):
    """Verify the chain, then write the windowed CSV + manifest.

    Returns 0 on success, 1 if the chain fails verification (nothing is
    written in that case: no evidence file from a broken chain)."""
    silent = lambda *a, **k: None  # noqa: E731
    if not verify_log(log_path, out=silent):
        out(f"REFUSED: {log_path} fails verification; no export written.")
        return 1
    records = load_records(log_path)
    window = [r for r in records if in_window(r, start, end)]
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for record in window:
            writer.writerow(_row(record))
    with open(out_path, "rb") as fh:
        csv_sha256 = hashlib.sha256(fh.read()).hexdigest()
    manifest = build_manifest(
        records, window, source_log=log_path, start=start, end=end, verified=True,
        csv_sha256=csv_sha256,
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
