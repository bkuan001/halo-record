"""Claude Code PostToolUse hook — zero-instrumentation auto-capture.

Reads a Claude Code PostToolUse event as JSON on stdin and appends one Halo
Runtime Record per tool call to a local log. This is the frictionless on-ramp:
no code changes, just a hook entry in Claude Code settings. It records — it
never blocks (PostToolUse fires only after a tool has already run).

Wire it up in ``~/.claude/settings.json``:

    {
      "hooks": {
        "PostToolUse": [
          {"matcher": "*", "hooks": [{"type": "command", "command": "halo hook"}]}
        ]
      }
    }

The log path is ``$HALO_LOG`` if set, else ``~/.halo/audit.jsonl``.
Set ``HALO_AUTHORITY_FILE`` to a JSON file containing a privacy-safe authority
snapshot (hashes/refs only) to stamp each captured Claude Code action with the
rules and tool registry that governed the run.
Set ``HALO_AGENT_VERSION`` and ``HALO_AGENT_MODEL`` to bind each record to the
agent build and model that produced it, so exports can answer "which version
was running?" for any audit window.
"""

import json
import os
import sys

from .capture import derive_outcome
from .record import Recorder, TenantRecorder, build

# Pure-reasoning / orchestration tools that touch no data, network, or external
# state are not trust-boundary actions, so they are not recorded.
SKIP_TOOLS = {"TodoWrite", "ExitPlanMode", "Task", "Skill", "BashOutput", "KillShell"}

ACTION_TYPE_BY_CLASS = {
    "connector": "tool_call",
    "exec": "tool_call",
    "data_write": "write",
    "data_read": "read",
    "network": "network",
    "other": "tool_call",
}
CATEGORY_BY_CLASS = {
    "connector": "security",
    "exec": "security",
    "data_write": "safety",
    "data_read": "privacy",
    "network": "security",
    "other": "security",
}


def action_class(tool_name):
    if not tool_name or tool_name in SKIP_TOOLS:
        return None
    if tool_name.startswith("mcp__"):
        return "connector"
    if tool_name == "Bash":
        return "exec"
    if tool_name in ("Write", "Edit", "NotebookEdit"):
        return "data_write"
    if tool_name in ("Read", "Glob", "Grep", "LS", "NotebookRead"):
        return "data_read"
    if tool_name in ("WebFetch", "WebSearch"):
        return "network"
    return "other"


def derive_scope(cls, tool_name):
    if cls == "connector":
        # Only MCP-named tools (mcp__<server>__<tool>) get an mcp: scope; a
        # plain framework tool that classified as a connector is just that.
        parts = tool_name.split("__")
        if tool_name.startswith("mcp__") and len(parts) > 1:
            return "mcp:" + parts[1]
        return "connector"
    return {
        "data_read": "fs.read",
        "data_write": "fs.write",
        "exec": "exec",
        "network": "network",
    }.get(cls, "tool")


def log_path():
    return os.environ.get("HALO_LOG", os.path.expanduser("~/.halo/audit.jsonl"))


def hook_agent(event=None):
    """Agent identity for captured records, with best-effort version binding.

    Version/model come from the event when present, else from
    ``HALO_AGENT_VERSION`` / ``HALO_AGENT_MODEL``. Optional by design: a
    record without them still verifies, but only a versioned record can say
    which agent build it describes."""
    agent = {"id": "claude-code", "name": "claude-code"}
    event_agent = (event or {}).get("agent")
    if isinstance(event_agent, dict):
        agent.update({k: v for k, v in event_agent.items() if isinstance(v, str)})
    version = os.environ.get("HALO_AGENT_VERSION")
    model = os.environ.get("HALO_AGENT_MODEL")
    if version and "version" not in agent:
        agent["version"] = version
    if model and "model" not in agent:
        agent["model"] = model
    return agent


def load_authority(path):
    """Load an optional privacy-safe authority snapshot from JSON.

    The file should contain hashes/refs/capability flags, not raw prompts,
    customer policy text, secrets, or private tool arguments. Hook capture is
    best-effort: malformed snapshots are ignored so the recorder never blocks
    the agent.
    """
    if not path:
        return None
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def record_event(event, recorder, *, subject=None, authority=None, summaries=True):
    """Build and append a record for one PostToolUse event. Returns the record,
    or None if the tool is skipped. An event-level ``subject`` overrides the
    caller-supplied default."""
    tool_name = event.get("tool_name") or event.get("tool") or ""
    cls = action_class(tool_name)
    if cls is None:
        return None
    tool_input = event.get("tool_input", {})
    record = build(
        ACTION_TYPE_BY_CLASS.get(cls, "tool_call"),
        CATEGORY_BY_CLASS.get(cls, "security"),
        tool=tool_name,
        tool_input=tool_input,
        session_id=event.get("session_id") or "local",
        agent=hook_agent(event),
        scope=derive_scope(cls, tool_name),
        outcome=derive_outcome(event.get("tool_response")),
        subject=event.get("subject") or subject,
        authority=event.get("authority") or authority,
        summaries=summaries,
    )
    recorder.append(record)
    return record


def main(argv=None):
    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return 0  # never break the agent on a malformed event

    summaries = os.environ.get("HALO_HASH_ONLY", "") not in ("1", "true", "yes")
    subject = os.environ.get("HALO_SUBJECT")
    directory = os.environ.get("HALO_DIR")
    authority = load_authority(os.environ.get("HALO_AUTHORITY_FILE"))
    if directory:
        # Per-tenant routing: each customer to their own chain.
        recorder = TenantRecorder(directory)
    else:
        path = log_path()
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        recorder = Recorder(path)
    record_event(event, recorder, subject=subject, authority=authority, summaries=summaries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
