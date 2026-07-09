"""halo-record — open, tamper-evident runtime records for AI agents.

Public API:

    from halo_record import Recorder, build, verify_log

    rec = Recorder("audit.jsonl")
    rec.append(build("tool_call", "security", tool="Read",
                     tool_input={"path": "secrets.env"}))

    verify_log("audit.jsonl")   # -> True if schema + hash chain are intact
"""

__version__ = "0.2.5"

from .canon import canon, compute_hash, input_hash, GENESIS_PREV
from .capture import record, record_call, derive_outcome
from .record import Recorder, TenantRecorder, build, SCHEMA_VERSION
from .redact import scan, redact_text, redact_sample
from .verify import verify_log, validate_record, load_schema
from .anchor import Notary, checkpoint, verify_completeness
from .witness import anchor_remote, fetch_checkpoints
from .report import render, write_report
from .policy import (evaluate, evaluate_log, load_policy, load_records,
                     render_text, render_html, verdict_panel)
from .session import current_recorder, bind_recorder, reset_recorder
from .trace import trace

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "Recorder",
    "build",
    "trace",
    "current_recorder",
    "bind_recorder",
    "reset_recorder",
    "record",
    "record_call",
    "derive_outcome",
    "verify_log",
    "validate_record",
    "load_schema",
    "scan",
    "redact_text",
    "redact_sample",
    "canon",
    "compute_hash",
    "input_hash",
    "GENESIS_PREV",
    "Notary",
    "checkpoint",
    "verify_completeness",
    "anchor_remote",
    "fetch_checkpoints",
    "render",
    "write_report",
    "evaluate",
    "evaluate_log",
    "load_policy",
    "load_records",
    "render_text",
    "render_html",
    "verdict_panel",
]
