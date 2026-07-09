"""``halo`` command-line interface."""

import argparse
import json
import sys

from . import __version__
from .canon import GENESIS_PREV, compute_hash, input_hash
from .record import build
from .verify import verify_log


def _cmd_verify(args):
    ok = verify_log(args.log)
    return 0 if ok else 1


def _cmd_sample(args):
    rec1 = build(
        "tool_call", "security", tool="mcp__gmail__search_threads",
        tool_input={"query": "open invoices"},
        session_id="conv_9a2f",
        agent={"id": "claude-code", "name": "claude-code", "model": "claude-opus-4-8"},
        scope="gmail.read",
        outcome={"status": "ok", "summary": "postgres://****"},
    )
    rec2 = build(
        "write", "safety", tool="Write",
        tool_input={"path": "report.md", "bytes": 4096},
        session_id="conv_9a2f",
        agent={"id": "claude-code", "name": "claude-code"},
        scope="fs.write", decision="human_approved", approver="alice.chen",
        outcome={"status": "ok", "summary": "wrote report.md"},
    )
    prev = GENESIS_PREV
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        for rec in (rec1, rec2):
            rec["integrity"]["prev_hash"] = prev
            rec["integrity"]["hash"] = compute_hash(rec, prev)
            prev = rec["integrity"]["hash"]
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")
    finally:
        if args.out:
            out.close()
    if args.out:
        print("wrote %s" % args.out)
    return 0


def _cmd_hash(args):
    print(input_hash(json.loads(args.json)))
    return 0


def _cmd_export(args):
    from .export import export, parse_bound
    try:
        start = parse_bound(getattr(args, "from"), end=False)
        end = parse_bound(args.to, end=True)
    except ValueError as e:
        print(e)
        return 2
    return export(args.log, args.out, start=start, end=end,
                  manifest_path=args.manifest)


def _cmd_hook(args):
    from .hook import main as hook_main
    return hook_main()


def _cmd_report(args):
    from .report import write_report
    out = args.out or (args.log.rsplit(".", 1)[0] + ".html")
    _, count = write_report(args.log, out, witness_log=args.witness,
                            witness_url=args.witness_url, policy_path=args.policy)
    print("wrote %s (%d records)" % (out, count))
    return 0


def _cmd_policy(args):
    from .policy import evaluate_log, render_text, render_html
    result = evaluate_log(args.log, args.policy)
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, subject=args.subject))
        print("wrote %s" % args.html)
    else:
        print(render_text(result))
    # CI-friendly: non-zero exit when the activity violates policy
    return 0 if result["compliant"] else 1


def _cmd_anchor(args):
    from .anchor import Notary, verify_completeness, _subject_id
    from .report import _load
    records = _load(args.log)

    if args.remote:
        from .witness import anchor_remote, fetch_checkpoints
        if not args.key:
            print("anchor --remote requires --key (the vendor bearer key)", file=sys.stderr)
            return 2
        if args.check:
            cps = fetch_checkpoints(args.remote, subject=_subject_id(records))
            result = verify_completeness(records, cps)
            status = {True: "COMPLETE", False: "INCOMPLETE", None: "UNWITNESSED"}[result["ok"]]
            print("%s — %s" % (status, json.dumps(result)))
            return 0 if result["ok"] is not False else 1
        cp = anchor_remote(args.remote, args.key, records)
        print("anchored to %s: subject=%s count=%d head=%s"
              % (args.remote, cp.get("subject") or cp.get("chain_root"),
                 cp["count"], cp["head"]))
        return 0

    if not args.witness:
        print("anchor requires a local witness path, or --remote <url> --key <k>",
              file=sys.stderr)
        return 2
    notary = Notary(args.witness)
    if args.check:
        result = verify_completeness(records, notary.checkpoints())
        status = {True: "COMPLETE", False: "INCOMPLETE", None: "UNWITNESSED"}[result["ok"]]
        print("%s — %s" % (status, json.dumps(result)))
        return 0 if result["ok"] is not False else 1
    cp = notary.witness(records)
    print("witnessed %s: count=%d head=%s" % (cp.get("subject") or cp.get("chain_root"),
                                              cp["count"], cp["head"]))
    return 0


def _cmd_serve(args):
    from .serve import serve
    return serve(args.dir, host=args.host, port=args.port, witness=args.witness,
                 gated=not args.open, verify=args.verify_email,
                 witness_url=args.witness_url)


def _cmd_grant(args):
    from . import access
    allow = access.grant(args.dir, args.chain, args.recipient)
    print("recipients for %s: %s" % (args.chain, ", ".join(allow)))
    return 0


def _cmd_report_views(args):
    from . import access
    views = access.read_leads(args.dir)
    for view in views:
        print("%s  %-28s  %s" % (view.get("ts", ""), view.get("email", ""),
                                 view.get("chain", "")))
    print("%d report view(s)." % len(views))
    return 0


def _cmd_demo(args):
    from .demo import main as demo_main
    return demo_main(args.dir, serve=args.serve, host=args.host, port=args.port,
                     verify=args.verify_email, open_browser=not args.no_open)


def _cmd_witness_serve(args):
    from .witness import serve
    return serve(args.store, host=args.host, port=args.port)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="halo",
        description="Halo Runtime Record — tamper-evident records for AI agents.")
    parser.add_argument("--version", action="version",
                        version="halo-record %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    p_verify = sub.add_parser("verify", help="verify a JSONL log's schema + hash chain")
    p_verify.add_argument("log", help="path to the .jsonl log")
    p_verify.set_defaults(func=_cmd_verify)

    p_sample = sub.add_parser("sample", help="emit a valid example log")
    p_sample.add_argument("out", nargs="?", help="output path (default: stdout)")
    p_sample.set_defaults(func=_cmd_sample)

    p_hash = sub.add_parser("hash", help="print the canonical sha256: hash of a JSON value")
    p_hash.add_argument("json", help="a JSON document, e.g. '{\"query\":\"x\"}'")
    p_hash.set_defaults(func=_cmd_hash)

    p_export = sub.add_parser(
        "export",
        help="date-bounded, workpaper-ready evidence export: CSV (one row per "
             "record) + a manifest tying it to the chain head; refuses to run "
             "on a chain that fails verification")
    p_export.add_argument("log", help="path to a JSONL chain")
    p_export.add_argument("--from", dest="from", default=None,
                          help="inclusive start (YYYY-MM-DD or RFC 3339)")
    p_export.add_argument("--to", default=None,
                          help="inclusive end (YYYY-MM-DD covers the whole day)")
    p_export.add_argument("-o", "--out", default="evidence.csv",
                          help="CSV output path (default: evidence.csv)")
    p_export.add_argument("--manifest", default=None,
                          help="manifest path (default: <out>.manifest.json)")
    p_export.set_defaults(func=_cmd_export)

    p_hook = sub.add_parser(
        "hook",
        help="Claude Code PostToolUse hook: read an event on stdin, append a record "
             "(env: HALO_LOG, or HALO_DIR + HALO_SUBJECT for per-tenant, HALO_HASH_ONLY)")
    p_hook.set_defaults(func=_cmd_hook)

    p_report = sub.add_parser(
        "report",
        help="render one tenant's JSONL chain as a self-verifying HTML trust report")
    p_report.add_argument("log", help="path to the .jsonl log (one subject/chain)")
    p_report.add_argument("-o", "--out", help="output .html path (default: alongside the log)")
    p_report.add_argument("-w", "--witness",
                          help="local notary witness log to embed a completeness verdict")
    p_report.add_argument("--witness-url",
                          help="hosted Halo witness URL the report fetches live (completeness "
                               "checked against a party the vendor doesn't control)")
    p_report.add_argument("--policy",
                          help="policy JSON file to corroborate the chain against; adds a "
                               "deterministic verdict (vendor / buyer / framework rules) to the report")
    p_report.set_defaults(func=_cmd_report)

    p_policy = sub.add_parser(
        "policy",
        help="corroborate a chain against a declarative policy (vendor / buyer / "
             "framework rules): per-rule pass / violation / evidence-gap verdict. "
             "Evaluative only, never enforcement. Non-zero exit on violation.")
    p_policy.add_argument("log", help="path to the .jsonl chain")
    p_policy.add_argument("policy", help="path to a policy JSON file (list of rules, or {\"rules\":[...]})")
    p_policy.add_argument("--html", help="write the verdict panel as standalone HTML to this path")
    p_policy.add_argument("--json", action="store_true", help="emit the raw result as JSON")
    p_policy.add_argument("--subject", help="subject/tenant label for the report footer")
    p_policy.set_defaults(func=_cmd_policy)

    p_anchor = sub.add_parser(
        "anchor",
        help="notary: witness a chain's head (local file or a hosted Halo witness), "
             "or --check a chain for completeness")
    p_anchor.add_argument("log", help="path to the .jsonl chain to witness/check")
    p_anchor.add_argument("witness", nargs="?",
                          help="path to a local append-only witness log "
                               "(omit when using --remote)")
    p_anchor.add_argument("--remote",
                          help="URL of a hosted Halo witness (e.g. https://witness.example) "
                               "to anchor to / check against instead of a local file")
    p_anchor.add_argument("--key",
                          help="vendor bearer key for --remote anchoring")
    p_anchor.add_argument("--check", action="store_true",
                          help="verify completeness against existing witnesses instead of adding one")
    p_anchor.set_defaults(func=_cmd_anchor)

    p_serve = sub.add_parser(
        "serve", help="serve per-tenant runtime reports over HTTP, access-scoped per customer")
    p_serve.add_argument("dir", help="directory of <subject>.jsonl chains (TenantRecorder output)")
    p_serve.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8721, help="bind port (default: 8721)")
    p_serve.add_argument("-w", "--witness", help="local notary witness log for completeness verdicts")
    p_serve.add_argument("--witness-url",
                         help="hosted Halo witness URL the served report fetches live for completeness")
    p_serve.add_argument("--open", action="store_true",
                         help="disable the email gate (serve reports to anyone with the link)")
    p_serve.add_argument("--verify-email", action="store_true",
                         help="require a one-time code emailed to the recipient (proves "
                              "ownership; dev mode logs the code, real mode uses $HALO_SMTP_HOST)")
    p_serve.set_defaults(func=_cmd_serve)

    p_grant = sub.add_parser(
        "grant", help="designate a recipient (email or domain) for a chain's report")
    p_grant.add_argument("dir", help="the served directory of chains")
    p_grant.add_argument("chain", help="chain name (the <subject>.jsonl stem)")
    p_grant.add_argument("recipient", help="an email (alice@acme-corp.com) or domain (acme-corp.com)")
    p_grant.set_defaults(func=_cmd_grant)

    p_views = sub.add_parser(
        "viewers", help="list who has unlocked a gated report (time, email, report)")
    p_views.add_argument("dir", help="the served directory of chains")
    p_views.set_defaults(func=_cmd_report_views)

    p_demo = sub.add_parser(
        "demo",
        help="scaffold a believable two-customer vendor runtime (record -> witness "
             "-> grant -> gated report) and print the links; --serve to go live")
    p_demo.add_argument("dir", nargs="?",
                        help="target dir (default: a fresh temp dir)")
    p_demo.add_argument("--serve", action="store_true",
                        help="boot the gated server after scaffolding")
    p_demo.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p_demo.add_argument("--port", type=int, default=8721, help="bind port (default: 8721)")
    p_demo.add_argument("--verify-email", action="store_true",
                        help="require a one-time code (proves recipient owns the email)")
    p_demo.add_argument("--no-open", action="store_true",
                        help="do not auto-open the operator console in a browser")
    p_demo.set_defaults(func=_cmd_demo)

    p_wserve = sub.add_parser(
        "witness-serve",
        help="run the hosted Halo witness: vendors anchor chain heads here over "
             "HTTP (append-only); viewers fetch completeness checkpoints")
    p_wserve.add_argument("store", help="directory for the append-only witness store")
    p_wserve.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p_wserve.add_argument("--port", type=int, default=8730, help="bind port (default: 8730)")
    p_wserve.set_defaults(func=_cmd_witness_serve)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
