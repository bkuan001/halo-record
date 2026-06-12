"""One-command demo: instrument -> witness -> grant -> gated serve.

``halo demo`` scaffolds a believable vendor agent runtime for two customers using
the real recording path (``TenantRecorder`` + ``build``), anchors the chains with
the notary, designates recipients, and prints the exact links to open. It is the
whole Halo loop in one shot — meant to be run live and screen-shared.

Story it tells: a customer-support AI vendor runs a *scoped pilot* of its
support agent ("Ferb") for two customers, Acme Corp and Initech. The agent
works on each tenant's customer data — looks up accounts, drafts replies with
an LLM, issues refunds — so the buyer's question is sharp: what exactly did
this agent do with my customers' data, which model saw it, and was anything
sensitive done without a human's sign-off? Every action (including each model
call, with provider and zero-data-retention disclosed) lands in that tenant's
own isolated chain. Their security teams open a private, email-gated Runtime
Report that re-verifies integrity *and* completeness in the browser. Acme can
never see Initech's chain.

The per-tenant chain therefore implies the customer is *already running the
agent* in a pilot — not a cold prospect. That's the honest moment for this
artifact: a buyer with real exposure deciding whether to expand.
"""

import os
import tempfile

from .anchor import Notary
from .record import TenantRecorder, build
from . import access as _access
from .serve import admin_key, load_secret, token_for

AGENT = {"id": "ferb-agent", "name": "Ferb Support Agent", "model": "claude-opus-4-8"}

# (subject, [actions]) — each action: (action_type, category, tool, tool_input,
#  scope, decision, approver, outcome, source). ``source`` is the on-ramp that
#  observed the call; the demo deliberately mixes captured (recorder, mcp) and
#  ingested (otel, litellm, langfuse, gateway) sources so the Runtime Report
#  shows honest, varied provenance. The action mix answers the buyer's
#  universal questions: tenant isolation, model-provider disclosure (with
#  zero-data-retention), human review before sensitive actions, and residency.
_RUNTIME = {
    ("acme-corp", "Acme Corp"): [
        ("read", "privacy", "mcp__crm__get_customer",
         {"tenant": "acme-corp", "customer": "cust_8841", "region": "us-east-1"}, "mcp:crm", "allowed", None,
         {"status": "ok", "summary": "looked up account + order history, tenant-scoped"}, "mcp"),
        ("read", "privacy", "mcp__zendesk__get_ticket",
         {"tenant": "acme-corp", "ticket": "ZD-30412"}, "mcp:zendesk", "allowed", None,
         {"status": "ok", "summary": "read ticket thread (4 messages)"}, "recorder"),
        ("tool_call", "privacy", "model.generate",
         {"provider": "anthropic", "model": "claude-opus-4-8", "zdr": True,
          "purpose": "draft reply to ticket ZD-30412", "messages": 6},
         "model:anthropic", "allowed", None,
         {"status": "ok", "summary": "reply drafted (zero-data-retention)"}, "litellm"),
        ("write", "safety", "refund.issue",
         {"tenant": "acme-corp", "order": "ord_2291", "amount_usd": 48}, "billing.write",
         "human_approved", "casey.lead@support.example",
         {"status": "ok", "summary": "$48 refund issued after human approval"}, "recorder"),
        ("network", "security", "email.send",
         {"tenant": "acme-corp", "to_domain": "acme-corp.com", "ticket": "ZD-30412"}, "network",
         "allowed", None,
         {"status": "ok", "summary": "reply sent to customer"}, "otel"),
        ("tool_call", "reliability", "mcp__jira__create_ticket",
         {"tenant": "acme-corp", "issue": "recurring billing bug behind ZD-30412"}, "mcp:jira", "allowed", None,
         {"status": "ok", "summary": "escalation FERB-218 created"}, "langfuse"),
    ],
    ("initech", "Initech"): [
        ("read", "privacy", "mcp__crm__get_customer",
         {"tenant": "initech", "customer": "cust_1102", "region": "us-west-2"}, "mcp:crm", "allowed", None,
         {"status": "ok", "summary": "looked up account, tenant-scoped"}, "gateway"),
        ("tool_call", "privacy", "model.generate",
         {"provider": "anthropic", "model": "claude-opus-4-8", "zdr": True,
          "purpose": "summarize ticket backlog", "messages": 3},
         "model:anthropic", "allowed", None,
         {"status": "ok", "summary": "backlog summary drafted (zero-data-retention)"}, "litellm"),
    ],
}


def emit_runtime(directory):
    """Write the demo runtime through the real per-tenant recorder."""
    rec = TenantRecorder(directory)
    counts = {}
    for (sid, sname), actions in _RUNTIME.items():
        for (atype, cat, tool, tinput, scope, decision, approver, outcome, source) in actions:
            record = build(
                atype, cat, tool=tool, tool_input=tinput,
                session_id="demo-" + sid,
                agent=AGENT, scope=scope, decision=decision, approver=approver,
                outcome=outcome, subject={"id": sid, "name": sname}, source=source)
            rec.append(record)
        counts[sid] = len(actions)
    return counts


def scaffold(directory):
    """Emit the runtime, witness every chain, and designate recipients.
    Returns (witness_path, {chain: recipient})."""
    counts = emit_runtime(directory)
    witness = os.path.join(directory, ".witness.jsonl")
    notary = Notary(witness)
    grants = {"acme-corp": "acme-corp.com", "initech": "initech.com"}
    from .report import _load
    for chain in counts:
        notary.witness(_load(os.path.join(directory, chain + ".jsonl")))
        _access.grant(directory, chain, grants[chain])
    return witness, grants, counts


def main(directory=None, *, serve=False, host="127.0.0.1", port=8721, verify=False,
         open_browser=True):
    created = directory is None
    directory = os.path.expanduser(directory) if directory else tempfile.mkdtemp(prefix="halo-demo-")
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    witness, grants, counts = scaffold(directory)
    secret = load_secret(directory)

    print("Halo demo scaffolded in %s%s" % (directory, " (temp)" if created else ""))
    print("  scenario: %s in a scoped pilot for %d prospect(s) (security review to clear rollout)"
          % (AGENT["name"], len(counts)))
    for chain, n in counts.items():
        print("    - %-10s %d actions, witnessed, shared with @%s"
              % (chain, n, grants[chain]))
    print()
    base = "http://%s:%s" % (host, port)
    print("Links once serving:")
    print("  operator console : %s/?key=%s" % (base, admin_key(secret)))
    for chain in counts:
        print("  %-10s report : %s/r/%s" % (chain, base, token_for(secret, chain)))
    print()
    print("Demo beats:")
    print("  1. Open Acme's link -> email gate. Enter alice@acme-corp.com -> report.")
    print("  2. The browser re-checks the hash chain AND completeness, both green.")
    print("  3. Note the model.generate entries: provider + zero-data-retention,")
    print("     disclosed per call — the buyer's first question, answered.")
    print("  4. Try bob@initech.com on Acme's link -> denied (wrong recipient).")
    print("  5. Drop a line from %s/acme-corp.jsonl and reload -> completeness goes RED,"
          % directory)
    print("     even though the (shortened) hash chain still verifies. That gap is")
    print("     the part only an independent witness catches.")
    print("  6. `halo leads %s` -> every reviewer who opened a report." % directory)

    if serve:
        print()
        if open_browser:
            import threading
            import webbrowser
            console = "%s/?key=%s" % (base, admin_key(secret))
            opener = threading.Timer(1.0, webbrowser.open, [console])
            opener.daemon = True
            opener.start()
        from .serve import serve as serve_fn
        return serve_fn(directory, host=host, port=port, witness=witness,
                        gated=True, verify=verify)
    else:
        print()
        print("To go live:  halo serve %s --witness %s%s"
              % (directory, witness, " --verify-email" if verify else ""))
    return 0
