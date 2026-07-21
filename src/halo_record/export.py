"""Date-bounded, workpaper-ready evidence export.

Auditors collect evidence over an audit period, in formats that drop into
working papers: flat files, one row per event, dated. ``halo export`` turns a
chain (or a window of it) into exactly that — a CSV of one row per record —
plus a small JSON manifest that ties the export back to the verifiable chain
it came from (chain head hash, record counts, window bounds).

The CSV is a review surface, not the evidence itself: full fidelity stays in
the chain, and the manifest's head hash is the link between the two. The
export refuses to run on a chain that fails verification — an evidence file
should never outlive the integrity of its source.

Dates are inclusive: ``--from 2026-06-01 --to 2026-06-30`` covers the whole
of June 30. Timestamps are compared in UTC.

Rows carry the agent build and model that produced them (``agent_version``,
``model``, ``model_version``) whenever the chain recorded those fields — an
audit answer is only as strong as its binding to the version that was
actually running during the window.
"""

import csv
import datetime
import json
import os

from .verify import verify_log

CSV_COLUMNS = [
    "ts",
    "record_id",
    "session_id",
    "subject",
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


def _row(record):
    action = record.get("action") or {}
    authority = record.get("authority") or {}
    subject = record.get("subject") or {}
    agent = record.get("agent") or {}
    findings = record.get("findings") or []
    return {
        "ts": record.get("ts", ""),
        "record_id": record.get("record_id", ""),
        "session_id": record.get("session_id", ""),
        "subject": subject.get("id", ""),
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


def build_manifest(records, window_records, *, source_log, start=None, end=None, verified=None):
    def _iso(dt):
        return dt.isoformat() if dt else None

    manifest = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_log": os.path.basename(str(source_log)),
        "window": {"from": _iso(start), "to": _iso(end)},
        "window_records": len(window_records),
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
    manifest = build_manifest(
        records, window, source_log=log_path, start=start, end=end, verified=True
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
