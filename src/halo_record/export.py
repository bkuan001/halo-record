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

from .verify import parse_record_line, read_log_lines, verify_log

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
    "approver",
    "scope",
    "authority_snapshot",
    # what a verification / policy gate said at run time (as supplied)
    "verification_status",
    "verification_verifier",
    "verification_policy_ref",
    "verification_checked_at",
    # what was flagged
    "severity",
    "findings",
    "threats",
    "pii_types",
    # data handling declared on the record
    "region",
    "cross_region",
    "purpose",
    # provenance
    "source",
    "session_id",
    # identity + verification
    "record_id",
    "parent_id",
    "input_hash",
    "prev_hash",
    "hash",
]


# Column dictionary carried in the manifest. Keep in step with CSV_COLUMNS
# (test_manifest_column_notes_cover_every_column guards it).
COLUMN_NOTES = {
    "ts": {"source": "recorder", "blank": "never",
           "note": "the recording host's clock when the record was built; sealed into the "
                   "chain but not attested by a third party (see chain.ts_source)"},
    "action_type": {"source": "recorder", "blank": "never"},
    "category": {"source": "recorder", "blank": "never"},
    "tool": {"source": "recorder", "blank": "no tool named"},
    "action_summary": {"source": "recorder", "blank": "no arguments recorded",
                       "note": "redacted summary; raw arguments never exported"},
    "outcome": {"source": "declared", "blank": "no outcome sealed"},
    "outcome_summary": {"source": "declared", "blank": "no outcome summary"},
    "subject": {"source": "declared", "blank": "untenanted chain"},
    "subject_name": {"source": "declared", "blank": "not supplied"},
    "principal": {"source": "declared", "blank": "not supplied"},
    "agent": {"source": "declared", "blank": "not supplied"},
    "agent_version": {"source": "declared", "blank": "not supplied"},
    "model": {"source": "declared", "blank": "not supplied"},
    "model_version": {"source": "declared", "blank": "not supplied"},
    "decision": {"source": "declared", "blank": "no authorization gate reported",
                 "note": "present only when the integration supplied a decision; never defaulted"},
    "approver": {"source": "declared", "blank": "no approver supplied",
                 "note": "an assertion sealed as supplied; not tied to an identity provider"},
    "scope": {"source": "declared", "blank": "not supplied"},
    "authority_snapshot": {"source": "declared", "blank": "no authority snapshot sealed"},
    "verification_status": {"source": "declared", "blank": "no verification claim supplied",
                            "note": "allowed / blocked / modified / unverified, as the "
                                    "reporting gate supplied it; not re-checked by the recorder"},
    "verification_verifier": {"source": "declared", "blank": "not supplied"},
    "verification_policy_ref": {"source": "declared", "blank": "not supplied"},
    "verification_checked_at": {"source": "declared", "blank": "not supplied"},
    "severity": {"source": "recorder", "blank": "no findings",
                 "note": "highest redaction-scanner finding, not a risk rating"},
    "findings": {"source": "recorder", "blank": "no findings"},
    "threats": {"source": "declared", "blank": "none supplied"},
    "pii_types": {"source": "recorder", "blank": "none detected"},
    "region": {"source": "declared", "blank": "not declared"},
    "cross_region": {"source": "declared", "blank": "not declared (not 'false')"},
    "purpose": {"source": "declared", "blank": "not declared"},
    "source": {"source": "declared", "blank": "no source tag (older recorder, or none supplied)",
               "note": "capture:adapter — captured at the boundary vs ingested from telemetry; "
                       "declared by the integration that built the record (LIMITS §3)"},
    "session_id": {"source": "declared", "blank": "never"},
    "record_id": {"source": "recorder", "blank": "never"},
    "parent_id": {"source": "declared", "blank": "no parent action"},
    "input_hash": {"source": "recorder", "blank": "no arguments recorded",
                   "note": "sha256 over the canonical JSON of the arguments, or a sorted-key "
                           "compact JSON when they do not canonicalize (see LIMITS §14)"},
    "prev_hash": {"source": "recorder", "blank": "never"},
    "hash": {"source": "recorder", "blank": "never"},
}


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
    return [parse_record_line(ln) for ln in read_log_lines(os.path.expanduser(path))]


def in_window(record, start=None, end=None):
    ts = _parse_ts(record.get("ts"))
    if ts is None:
        # An unparseable timestamp cannot be placed in a window, so a bounded
        # export leaves it out (the manifest's counts disclose the gap). An
        # unbounded export is the whole population: nothing is dropped.
        return start is None and end is None
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


# Summaries the recorder writes are capped at 200 characters; anything far longer
# came from elsewhere and is shown as-is rather than parsed.
_LITERAL_MAX = 4096


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
        if (stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]")
                and len(stripped) <= _LITERAL_MAX):
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


_FORMULA_START = ("=", "+", "-", "@")


def _neutralize(value):
    """Defuse spreadsheet formula injection in a CSV cell.

    The export's target flow is "open in Excel/Sheets or upload to a GRC
    platform", and record fields (tool names, session ids, summaries) can be
    influenced by whatever the agent touched. A cell starting with ``=``,
    ``+``, ``-``, ``@``, or a control character (tab, CR, LF, ...) — or whose
    first non-whitespace character is a formula start, since some importers
    trim leading whitespace — would execute as a formula there, so those cells
    are prefixed with a single quote: the standard neutralization, displayed
    by spreadsheets as plain text."""
    if not isinstance(value, str) or not value:
        return value
    first = value[0]
    if first in _FORMULA_START or (ord(first) < 32) or first == "\x7f":
        return "'" + value
    if first.isspace() and value.lstrip()[:1] in _FORMULA_START:
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
    verification = record.get("verification")
    verification = verification if isinstance(verification, dict) else {}
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
        "approver": (action.get("authorization") or {}).get("approver", ""),
        "scope": (action.get("authorization") or {}).get("scope", ""),
        # Data-handling declarations sealed on the record (see data.* in the
        # schema). Exported as declared; the recorder does not verify them.
        "region": data.get("region", ""),
        "cross_region": ("" if data.get("cross_region") is None
                         else ("true" if data.get("cross_region") else "false")),
        "purpose": data.get("purpose", ""),
        "input_hash": (action.get("input") or {}).get("hash", ""),
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
        "verification_status": verification.get("status", ""),
        "verification_verifier": verification.get("verifier", ""),
        "verification_policy_ref": verification.get("policy_ref", ""),
        "verification_checked_at": verification.get("checked_at", ""),
        "hash": (record.get("integrity") or {}).get("hash", ""),
    }
    return {k: _neutralize(v) for k, v in row.items()}


TS_SOURCE = ("declared: each record's ts is the recording host's clock, sealed into the "
             "chain as written; it is not attested by a third party. An attested time "
             "exists only where a witness checkpoint carries an RFC 3161 token (verify "
             "it with openssl ts -verify).")


def build_manifest(records, window_records, *, source_log, start=None, end=None,
                   verified=None, csv_sha256=None, tools=None, source_log_sha256=None,
                   subject=None, witness=None, completeness=None):
    def _iso(dt):
        return dt.isoformat() if dt else None

    from . import __version__ as _producer_version
    if source_log_sha256 is None:
        try:
            with open(source_log, "rb") as fh:
                source_log_sha256 = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            source_log_sha256 = None
    manifest = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # Which halo-record produced this export (REVIEWERS.md's "produced with"
        # half of the citation line) and the exact chain file it was cut from.
        "producer_version": _producer_version,
        "source_log": os.path.basename(str(source_log)),
        "source_log_sha256": source_log_sha256,
        # What each column is and what a blank means, so the CSV can be read
        # without the source. "recorder" fields are computed or sealed by the
        # recorder; "declared" fields are sealed exactly as the integration
        # supplied them and are not verified by the recorder (LIMITS §10).
        "columns": COLUMN_NOTES,
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
            "ts_source": TS_SOURCE,
        },
        # Whose chain this is: the subject ids the records carry, and the id
        # the exporter expected (when one was given; a mismatch is refused).
        "subject": subject or {"ids": _subject_ids(records), "expected": None},
        # Which witness completeness was checked against, if any.
        "witness": witness,
        # COMPLETE / UNWITNESSED / NOT_CHECKED (an INCOMPLETE chain is refused).
        "completeness": completeness or {
            "status": "NOT_CHECKED",
            "note": "no witness was named; records removed and the chain re-sealed "
                    "would not be visible here (export --witness / --witness-url)"},
    }
    if window_records:
        manifest["window"]["first_ts"] = window_records[0].get("ts")
        manifest["window"]["last_ts"] = window_records[-1].get("ts")
        manifest["window"]["first_record_id"] = window_records[0].get("record_id")
        manifest["window"]["last_record_id"] = window_records[-1].get("record_id")
    return manifest


def _subject_ids(records):
    from .report import _record_subject
    return sorted({_record_subject(r) for r in records if isinstance(r, dict)},
                  key=lambda x: json.dumps(x))


def _completeness(records, *, witness_log=None, witness_url=None, expected_subject=None):
    """(witness_info, completeness_result) for the named witness, or (None, None).
    Raises ValueError when a named witness URL cannot be reached."""
    from .anchor import Notary, verify_completeness, _subject_id, chain_root
    if witness_log:
        cps = Notary(witness_log).checkpoints_for(records)
        info = {"kind": "local", "path": os.path.basename(str(witness_log))}
    elif witness_url:
        from .witness import fetch_checkpoints, WitnessDamagedError
        subj = expected_subject if expected_subject is not None else _subject_id(records)
        try:
            cps = fetch_checkpoints(witness_url, subject=subj,
                                    chain_root=(chain_root(records) if subj is None else None))
        except WitnessDamagedError:
            raise
        except Exception as e:
            raise ValueError("the witness at %s could not be reached (%s)" % (witness_url, e))
        info = {"kind": "url", "url": witness_url}
    else:
        return None, None
    result = verify_completeness(records, cps, expected_subject=expected_subject)
    info["checkpoints"] = result.get("witnessed", 0)
    info["operator_note"] = ("completeness is independent only if this witness is operated "
                             "by a party outside the vendor's control")
    return info, result


def export(log_path, out_path, *, start=None, end=None, tools=None,
           manifest_path=None, out=print, witness_log=None, witness_url=None,
           expected_subject=None):
    """Verify the chain, then write the windowed CSV + manifest.

    Returns 0 on success, 1 if the chain fails verification, carries an
    unexpected subject, conflicts with a named witness (INCOMPLETE), or the
    named witness cannot be reached; 3 if it holds no records — nothing is
    written in any of those cases — or if a named witness holds no checkpoints
    for it (UNWITNESSED: the export is written and its manifest says so);
    2 if the chain file cannot be read, the named local witness file is missing
    or damaged, or the CSV or manifest cannot be written (a missing directory)."""
    silent = lambda *a, **k: None  # noqa: E731
    real_path = os.path.expanduser(str(log_path))
    m_path = manifest_path or (str(out_path) + ".manifest.json")
    for target in (out_path, m_path):
        parent = os.path.dirname(os.path.abspath(os.path.expanduser(str(target))))
        if not os.path.isdir(parent):
            out(f"REFUSED: cannot write {target}: directory {parent} does not exist; "
                "no export written.")
            return 2
    if witness_log and not os.path.isfile(os.path.expanduser(str(witness_log))):
        # A mistyped witness path must not read as "not anchored yet".
        out(f"REFUSED: witness file {witness_log} does not exist; no export written.")
        return 2
    # Snapshot the chain once, so verification, the exported rows, the head
    # hash and source_log_sha256 all describe the same bytes even if a
    # recorder appends while the export runs.
    try:
        with open(real_path, "rb") as fh:
            snapshot = fh.read()
    except OSError as exc:
        out(f"REFUSED: {log_path} is not a readable chain file ({exc.strerror}); no export written.")
        return 2
    source_log_sha256 = hashlib.sha256(snapshot).hexdigest()
    import tempfile
    snap = tempfile.NamedTemporaryFile(prefix=".halo-export-", suffix=".jsonl",
                                       dir=os.path.dirname(os.path.abspath(real_path)) or None,
                                       delete=False)
    try:
        snap.write(snapshot)
        snap.close()
        if not verify_log(snap.name, out=silent):
            out(f"REFUSED: {log_path} fails verification; no export written.")
            return 1
        records = load_records(snap.name)
    finally:
        try:
            os.unlink(snap.name)
        except OSError:
            pass
    # An empty population is nothing to attest, not a clean evidence file: a
    # header-only CSV under a manifest that says "verified" would read as a
    # verified empty history. Refuse and write nothing (exit 3, like verify).
    if not records:
        out(f"REFUSED: {log_path} holds 0 records — nothing to attest; no export written.")
        return 3
    ids = _subject_ids(records)
    if expected_subject is not None and ids != [expected_subject]:
        out(f"REFUSED: {log_path} carries subject id(s) {json.dumps(ids)}, not exactly the "
            f"expected {json.dumps(expected_subject)}; no export written.")
        return 1
    from .anchor import WitnessFileError
    try:
        witness_info, comp = _completeness(records, witness_log=witness_log,
                                           witness_url=witness_url,
                                           expected_subject=expected_subject)
    except WitnessFileError as e:
        out(f"REFUSED: {e}; no export written.")
        return 2  # as for a missing witness file
    except (ValueError, OSError) as e:
        out(f"REFUSED: {e}; no export written.")
        return 1
    completeness = None
    if comp is not None:
        status = {True: "COMPLETE", False: "INCOMPLETE", None: "UNWITNESSED"}[comp.get("ok")]
        if status == "INCOMPLETE":
            out(f"REFUSED: INCOMPLETE — {log_path} conflicts with the witness "
                f"({json.dumps(comp)}); no export written.")
            return 1
        completeness = {"status": status, "detail": comp}
    window = [r for r in records
              if in_window(r, start, end) and matches_tools(r, tools)]
    if not window:
        # An empty window over a real chain is legitimate evidence ("no
        # recorded actions in this period") and the manifest discloses it as
        # window_records: 0 — but say it aloud so a scripted export never
        # passes an inverted window or a misspelled tool off as a quiet quarter.
        out(f"NOTE: 0 of {len(records)} records match the window/tool filter; "
            "the export is header-only and the manifest records window_records: 0.")
    try:
        with open(out_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for record in window:
                writer.writerow(_row(record))
    except OSError as exc:
        out(f"REFUSED: cannot write {out_path} ({exc.strerror or exc}); no export written.")
        return 2
    with open(out_path, "rb") as fh:
        csv_sha256 = hashlib.sha256(fh.read()).hexdigest()
    manifest = build_manifest(
        records, window, source_log=log_path, start=start, end=end, verified=True,
        csv_sha256=csv_sha256, tools=tools, source_log_sha256=source_log_sha256,
        subject={"ids": ids, "expected": expected_subject},
        witness=witness_info, completeness=completeness,
    )
    try:
        with open(m_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        try:
            os.unlink(out_path)  # a CSV without its manifest is not evidence
        except OSError:
            pass
        out(f"REFUSED: cannot write {m_path} ({exc.strerror or exc}); no export written.")
        return 2
    out(
        f"exported {len(window)} of {len(records)} records -> {out_path} "
        f"(manifest: {m_path}; chain head {manifest['chain']['head_hash'][:16]}...)"
    )
    if completeness is None:
        out("NOTE: completeness NOT CHECKED — no witness named; the manifest attests "
            "integrity relative to the head only.")
    elif completeness["status"] == "UNWITNESSED":
        out("UNWITNESSED — the named witness holds no checkpoints for this chain; "
            "the manifest records completeness as UNWITNESSED.")
        return 3
    else:
        out("COMPLETE — every checkpoint the witness holds for this chain is present.")
        if witness_log:
            from .anchor import LOCAL_WITNESS_NOTE
            out(LOCAL_WITNESS_NOTE)
    return 0
