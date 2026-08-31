# halo-record

Tamper-evident **audit trails for AI agents** — hash-chained Runtime Records, rendered as a Runtime Report your customers can check themselves.

Every action your agent takes (tool calls, model calls, data access, approvals) becomes one **Runtime Record** in an append-only, hash-chained log; the **Runtime Report** is that chain rendered as a self-verifying HTML page. Any party holding a checkpoint of the chain can verify the records behind it were never altered, without trusting whoever produced them — that checkpoint is the load-bearing piece: the chain alone is tamper-evident against everyone except the party operating the recorder ([LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). When a customer's security team asks "what did your agent do with our data?", you hand them a link instead of a paragraph. Security reviews already ask AI questions next to the SOC 2 checklist — and increasingly those questions come from ISO 42001, the EU AI Act's record-keeping articles, and customers' own questionnaires. Today a written assurance still passes. The bet behind this project is that it won't for long.

**Featured in [Help Net Security](https://www.helpnetsecurity.com/2026/08/31/halo-record-open-source-ai-agent-audit-trail/)** (August 2026).

The record format is open and free to implement. This package is the reference implementation: recorder, verifier, witness client, and report server.

> **Using halo-record, or thinking about it?** Tell me who you are and what for → [Who's using halo-record?](https://github.com/bkuan001/halo-record/discussions/7)

## Check it yourself

You are being asked to put a recorder inside your agent. You should not take that on faith:

- **Zero runtime dependencies.** Standard library only. `pip install halo-record` installs exactly one package.
- **No network calls**, except two opt-in ones — the witness (receives only a record count and a chain fingerprint) and the RFC 3161 timestamp (sends only a checkpoint's state hash to a Timestamp Authority). Both are off unless you invoke them; record contents never leave your infrastructure.
- **Full payloads never enter a record.** Arguments are hashed and stored only as a short redacted summary — the complete raw value is never written, though a summary can carry fragments of it. Redaction is best-effort (regex over common secret and PII formats plus an entropy catch-all): treat it as defense-in-depth, not a guarantee.
- **Small enough to audit.** ~5,300 lines of Python (code lines, not counting blanks and comments). Read all of it in an afternoon.
- **Apache-2.0.**

## 60-second demo

No agent required. With [uv](https://docs.astral.sh/uv/), nothing to install:

```
uvx --from halo-record halo demo --serve
```

or the classic way:

```
pip install halo-record
halo demo --serve
```

Either one scaffolds a fictional support-agent vendor with two customers, witnesses the chains (with a local witness file standing in for one outside the operator — see [LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)), serves their gated Runtime Reports, and opens the operator console in your browser. Then try the tamper test: delete a line from one of the `.jsonl` files and reload. The report catches it.

## Record your own agent

One line at the boundary:

```python
from halo_record import trace

agent = trace(run_my_agent, profile="my-agent", log="audit.jsonl")   # wraps your entrypoint; records the run boundary to ./audit.jsonl — add record_call() or a framework adapter at each tool boundary to capture individual calls
```

A `from halo import ...` convenience shim also ships — but the `halo` name on PyPI belongs to an unrelated terminal-spinner package, and if that package is installed it wins the import. `halo_record` is unambiguous, so the examples use it.

Without `log=`, records go to `~/.halo/my-agent.jsonl` (one chain per agent). The wrapper seals the run boundary; the evidence lives in the per-call records. Capture those with a framework adapter (matrix below) — or explicitly, which also shows how delegation links:

```python
from halo_record import Recorder, record_call

rec = Recorder("audit.jsonl")

with record_call(rec, "crm.lookup", {"account": "acct-9"}) as call:            # one sealed record per tool call
    call.result = crm.lookup("acct-9")

with record_call(rec, "payments.refund", {"amount": 120},
                 parent_id=rec.last_record_id()) as call:                      # child links to the action that spawned it
    call.result = payments.refund(120)
```

Then render the report:

```
halo report audit.jsonl -o report.html    # one chain -> self-verifying HTML
halo serve ./records --port 8721          # all tenants, gated per customer
```

The quickstart ends when you are looking at your own agent's Runtime Report in a browser. If you got a JSONL file and no report, something is wrong: open an issue.

### The verification block

If a guardrail or policy layer checked the action, its verdict can ride on the record — an optional block recording what the gate decided, sealed into the hash chain like every other field:

```python
from halo_record import build

build("tool_call", "security", tool="payments.refund",
      verification={"status": "allowed", "verifier": "gate/1.2",
                    "policy_ref": "sha256:1f3a...",
                    "checked_at": "2026-08-01T12:00:00Z"})
```

which seals into the record as:

```json
"verification": {"status": "allowed", "verifier": "gate/1.2", "policy_ref": "sha256:1f3a...", "checked_at": "2026-08-01T12:00:00Z"}
```

`record_call(...)` accepts the same `verification=` keyword. `status` is required within the block; `verifier`, `policy_ref`, and `checked_at` are optional. What each status means:

| Status | What the gate reports | Did the action execute? |
|---|---|---|
| `allowed` | it permitted the action | yes — the action proceeded |
| `blocked` | it denied the action | determined by the integration, not by this field — a record may still carry an outcome, and a block does not by itself prove non-execution |
| `modified` | it altered the action before execution — `action.input` describes the action **as executed**, post-modification | yes, in the altered form |
| `unverified` | it ran (or was consulted) but made no determination — distinct from an absent block, which means no verification claim was made at all | yes — the action proceeded without a verdict |

The block is supplied by the operator's integration code and records what it reports the gate said — the same trust posture as `principal` (see [LIMITS](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md#11-verification-status-is-the-gates-report-not-halos-finding)). Sealing proves the status was not edited after the fact; it does not prove the check occurred, that the verdict was correct, or that a blocked action did not execute. This is not independent verification.

For `policy_ref` to be usable as evidence, use a content hash of the ruleset and retain the ruleset artifact — an unresolvable label makes the field decorative.

## Connect to what you already run

| Captured at the boundary | Ingested from existing telemetry |
|---|---|
| Native recorder (`from halo_record import trace`) | OpenTelemetry GenAI spans |
| MCP interceptor | LiteLLM callbacks |
| LangChain / LangGraph callback | Langfuse export |
| OpenAI Agents SDK hooks | Any gateway / reverse-proxy log |
| Claude Code / Claude Agent SDK hook | |

Framework adapters and ingestion paths stamp each record with a `source` tag, so the report discloses how each piece of evidence was collected. Captured and ingested records live in the same chain.

For LangChain / LangGraph, it is a callback handler:

```python
from halo_record import Recorder
from halo_record.integrations.langchain import HaloCallbackHandler

recorder = Recorder("audit.jsonl")
result = my_chain.invoke(inputs, config={"callbacks": [HaloCallbackHandler(recorder)]})   # every tool call becomes a record
```

For MCP, one call wraps the client session — and then *any* MCP-using agent emits records for every tool call, regardless of which framework drives it:

```python
from halo_record.integrations.mcp import instrument_client_session

instrument_client_session(session, Recorder("audit.jsonl"), server="stripe")   # every session.call_tool() is now recorded
```

For gateway or proxy logs (Cloudflare AI Gateway, Portkey, nginx in front of the model), map a log row into the chain — honestly tagged as ingested, not boundary-captured:

```python
from halo_record.integrations.gateway import record_log

record_log(Recorder("audit.jsonl"), {"tool": "gen_ai:gpt-4o", "model": "gpt-4o", "status": 200, "subject": "acme-corp"})
```

Anything that emits OpenTelemetry GenAI spans (CrewAI, LlamaIndex, and most agent frameworks with OTel instrumentation) lands in the chain through the OTel adapter, and the [TypeScript package](https://github.com/bkuan001/halo-record-ts) ships native adapters for the Vercel AI SDK and the JS agent ecosystem. Missing an adapter for your stack? Open an issue. Most adapters are about a hundred lines.

## Record your coding agent

Claude Code fires a `PostToolUse` hook after every tool call. Point it at `halo hook` and each action — file writes, shell commands, MCP connector calls — becomes a record in a local chain. No code changes; one settings entry:

```json
{
  "hooks": {
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "halo hook"}]}
    ]
  }
}
```

Add that to `~/.claude/settings.json` and records land in `~/.halo/audit.jsonl` (override with `$HALO_LOG`). Pure-orchestration tools that touch no data, network, or external state are skipped — the chain records trust-boundary actions, not thinking. Set `HALO_HASH_ONLY=1` to record content hashes without summaries. Set `HALO_AGENT_VERSION` (and optionally `HALO_AGENT_MODEL`) to bind every record to the agent build that produced it — when an auditor asks about the version that was running in a given window, the export answers by column instead of by recollection.

If you need the report to answer "under what rules did this run happen?", set `HALO_AUTHORITY_FILE` to a JSON snapshot of the effective authority for the session. Keep it privacy-safe: hashes and refs, not raw prompts, private policy text, secrets, or full tool schemas.

```json
{
  "snapshot_id": "auth_2026_07_08T1100Z",
  "captured_at": "2026-07-08T11:00:00Z",
  "scope": "session",
  "workspace": {"path_hash": "sha256:...", "git_commit": "abc1234"},
  "refs": [
    {"kind": "project_rules", "id": "CLAUDE.md", "hash": "sha256:...", "loaded": true, "truncated": false},
    {"kind": "mcp_tool_registry", "id": "filesystem", "hash": "sha256:..."}
  ],
  "omissions": [{"kind": "private_policy", "reason": "customer_secret", "hash": "sha256:..."}],
  "stale_if": ["project_rules_hash_changed", "mcp_tool_registry_hash_changed"]
}
```

```sh
HALO_AUTHORITY_FILE=./authority.json halo hook
```

The snapshot is sealed into the same hash chain as the action records. A good default is one session-level snapshot at start, plus a new snapshot when rules, Skills, hooks, MCP tool registries, or compaction policy change. To keep long sessions lean, consecutive records with the same `authority.snapshot_id` are compacted after the first full snapshot: later records keep only `{"snapshot_id": "...", "same_as_previous": true}`. The pointer stays hash-chained, but the bulky refs/omissions/stale-if block is not repeated on every action. Then, the usual:

```
halo verify ~/.halo/audit.jsonl
halo report ~/.halo/audit.jsonl -o report.html
```

Any agent runtime that exposes a post-action hook can feed the same command — the hook reads one event as JSON on stdin and appends one record.

One chain, one writer at a time. A chain is a linked list: two writers that read the same head and both append will fork it (two records claiming the same predecessor), and verification will name the affected records. `Recorder` serializes its own appends with a sidecar lock (POSIX `flock` here; a lock directory in the TypeScript package), and `halo hook` appends through `Recorder`, so the hook setup above is covered. Anything that writes the chain file directly — a hand-rolled hook, parallel workers, a log shipper — must hold an equivalent exclusive lock across the read-head-then-append sequence, or write to per-process chains. [LIMITS.md section 9](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md#9-single-writer-chains) covers this in full, including the cross-language boundary.

## When recording fails

The two integration styles fail in opposite directions, on purpose — pick the one whose failure you can live with:

- **Framework adapters (LangChain, hooks via callback managers) fail open.** If a record cannot be written (disk full, permissions), the agent's action completes normally and the record is lost. The LangChain handler prints a loud warning to stderr and counts the loss (`handler.lost_records`), but nothing in the chain itself can show a record that was never written — a stalled chain still verifies. Witness checkpoints on a cadence are what make a stalled chain visible: an expected checkpoint that never arrives is the alarm.
- **The native `trace()` wrapper fails closed.** If the record cannot be written, the exception propagates into the agent's action — no evidence, no action. Stricter, and it can interrupt your agent.

Neither default is right for everyone; know which one you are running.

## Integrity vs. completeness (read this part)

Be precise about what each layer proves — because they are different claims, and the differences are the point:

A self-held chain proves **integrity relative to an established head**: given a chain head someone already holds, any edit, reordering, or deletion in the records behind it becomes detectable. By itself — before anyone outside the operator has seen a head — a chain proves internal consistency, not history: an operator could drop a record and re-seal, and the new file would verify. The chain becomes **historically committed** the moment its head leaves the operator's control.

That is the witness: a party outside the operator holding periodic fingerprints of the chain (a count and a head hash, nothing else). Checkpoints make rewriting committed history detectable, and a missed checkpoint is itself a visible event:

```
halo anchor audit.jsonl witness.jsonl           # anchor a checkpoint to a local witness
halo anchor audit.jsonl witness.jsonl --check   # completeness verdict against it
```

For *time* specifically, an external RFC 3161 timestamp replaces the checkpoint's self-asserted clock with a proof from a Timestamp Authority the operator does not control — "this chain reached this head no later than T", verifiable by a third party with no hosted infrastructure. The default TSA is the free freetsa.org (fine for evaluation); point at a commercial TSA (DigiCert / Sectigo / your own) with `--tsa` for production:

```
halo anchor audit.jsonl witness.jsonl --timestamp          # attach a TSA time proof to the checkpoint
halo anchor audit.jsonl witness.jsonl --check              # reads the token's claimed time
```

`--check` confirms the token binds this chain state and reads its attested time, but it does **not** validate the TSA's signature — that is deliberately left to a standard tool so a reviewer trusts no code of ours. To verify the time independently (this is what you hand a security reviewer):

```
# tsa.token_b64 lives in the witness log; decode the latest one to a standard .tsr file
python3 -c 'import json,base64; cps=[json.loads(l) for l in open("witness.jsonl") if l.strip()]; t=[c["tsa"] for c in cps if c.get("tsa")][-1]; open("token.tsr","wb").write(base64.b64decode(t["token_b64"])); print(t["digest"])'
curl -s -o tsa-ca.pem https://freetsa.org/files/cacert.pem     # CA for the default TSA (a commercial TSA publishes its own)
openssl ts -verify -digest <the digest printed above> -in token.tsr -CAfile tsa-ca.pem   # → "Verification: OK"
```

One more boundary, stated plainly: neither the chain nor the witness proves that every real-world action passed through the recorder. That is **capture completeness** — a property of where the recorder sits in the stack (native instrumentation, hooks, gateway ingestion), not of any hash. Records carry a `source` tag for exactly this reason.

| Claim | Self-held chain | + External checkpoints | + Trusted capture |
|---|---|---|---|
| Detect edits to an established artifact | ✔ | ✔ | ✔ |
| Detect rewriting of committed history | — | ✔ | ✔ |
| Detect missing/late checkpoints | — | ✔ (agreed cadence) | ✔ |
| Prove every action was recorded | — | — | depends on capture boundary |

Anyone can run a witness. A witness you run yourself commits history to *you*; committing it to *your customer* requires a witness they have reason to trust. The protocol is open either way.

A hosted, recognized witness is how this project will sustain itself. Early access: brian@briankuan.com.

## Personal data in the chain

The chain is append-only: anything sealed into a record stays there, because
removing it would break verification for everything after it. Tool arguments are
already handled — stored as a hash plus a redacted summary, never raw.

Note the limit in that sentence: *redacted*, not removed. [LIMITS.md](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)
section 6 is explicit that a name or a postal address has no reliable pattern, so
neither is detected and neither is masked. And `subject` is not the only field that
carries text you supply — `principal`, `approver`, `session_id`, `agent`,
`authority`, `data` and the summaries all do.

The pattern that works: put a stable pseudonymous id in the chain and hold the
mapping to any individual in a system you can delete from. An erasure request is
then satisfied by deleting the mapping. Keep `subject` pointing at the tenant
organization, not a person:

```python
from halo_record import build

build("tool_call", "privacy", subject={"id": "acme", "name": "Acme Corp"})
```

No setting enforces this — it is a discipline in how you call the recorder.
It makes erasure tractable; it is not anonymization, and there is no built-in
retention or pruning yet.
[LIMITS.md section 13](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md#13-personal-data-and-erasure) has the full field
list, explains why the stored input fingerprint can confirm a guessable value even
after the mapping is gone, and ends with questions a reviewer should ask.

Record a model call (the buyer's first question: "which model saw my data?"):

```python
from halo_record import record_model_call

record_model_call(rec, provider="anthropic", model="claude-sonnet-4-6",
                  zdr=True, purpose="draft support reply",
                  subject="acme")   # tool=model.generate, scope=model:anthropic
```

## Where this sits in a compliance stack

halo-record is an evidence layer, not a certification. It produces the artifact that assessment frameworks keep asking for in different words. One scope note that governs every bullet below: these are integrity claims about the record; completeness against the operator requires an external witness holding checkpoints ([LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)).

- **Security questionnaires and SOC 2 reviews:** answer the AI sections with a verifiable Runtime Report instead of screenshots and prose.
- **AIUC-1:** produces the tamper-evident logging evidence (E015.4) and execution-chain records with authorization events (E015.2 — with a stated gap: reasoning traces are not captured) that the standard's Accountability controls call for. Once the chain is anchored to a witness the relying party has reason to trust — a witness the operator runs itself does not provide this — that's a continuously witnessed chain rather than one reconstructed at audit time (what entered the chain is still bounded by the capture surface). A control-by-control evidence mapping, including what's deliberately out of scope, is in [`AIUC.md`](https://github.com/bkuan001/halo-record/blob/main/AIUC.md).
- **OWASP Top 10 for Agentic Applications 2026:** eight of the ten threats map to deterministic policy rules over the record, two are marked out of scope with reasons, and the pack ships runnable. An approximate community mapping, not an official OWASP artifact. See [`OWASP.md`](https://github.com/bkuan001/halo-record/blob/main/OWASP.md).
- **AARM (CSA):** produces the tamper-evident action receipt AARM specifies — R5, and the sealing half of R6 (identity is sealed into the hash, not cryptographically authenticated). halo-record is the receipt layer; pair it with an enforcement gateway for a full AARM system. See [`AARM.md`](https://github.com/bkuan001/halo-record/blob/main/AARM.md).
- **Agentic Trust Controls:** the runtime records behind the ATC's evidence controls — tamper-evident action logging (RBM-03) and the record half of authority attestation (AID-05; the enforcement half belongs to the gate) in one chained record. See [`ATC.md`](https://github.com/bkuan001/halo-record/blob/main/ATC.md).
- **EU AI Act / ISO 42001 / NIST AI RMF:** the record-keeping and logging obligations these frameworks describe are the same artifact class; no control-by-control mapping is published here yet.

None of this certifies anything by itself. It gives your assessor something verifiable to look at. The boundaries — what halo-record deliberately does not do, and what to say when a reviewer asks — are documented in [`LIMITS.md`](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md).

### Getting the evidence into your GRC platform

Most GRC platforms (Vanta, Drata, and similar) accept uploaded files as custom evidence against a control. halo-record's export is built to drop into that flow:

```bash
halo export audit.jsonl --from 2026-06-01 --to 2026-06-30 -o evidence.csv

# scope the export to the actions a control covers
halo export audit.jsonl --from 2026-06-01 --to 2026-06-30 --tool email.send --tool db.query -o evidence.csv
```

This writes two files for the audit window: the CSV (one row per recorded action, grouped left to right as *when → what happened → who → under what authority → what was flagged → provenance → how to verify*, including a redacted plain-language summary of the call and its result, the agent build and model that produced each, the identity it ran on behalf of, the record it was caused by, its authorization decision and scope, and any personal-data categories or ingested threat flags) and a manifest (`evidence.csv.manifest.json`) that ties the CSV to its source — the chain's head hash links it to the verifiable log it came from, and `csv_sha256` is the exported file's own hash, so a CSV edited after export no longer matches its manifest. Narrow the population with `--tool` when a control only covers certain actions; the manifest records the filter, so a scoped export discloses that it is a subset rather than reading as the whole population. Upload both against your logging or monitoring control; attach the Runtime Report HTML when a reviewer wants to verify the chain themselves. The export refuses to run on a chain that fails verification.

A native push integration — evidence landing in your platform automatically — is on the roadmap. The file path above works today with any platform that accepts uploaded evidence.

## CLI

```
halo verify   validate schema + hash chain (exit 1 broken, 3 empty chain; CI-friendly)
halo report   render a chain as a self-verifying HTML Runtime Report
              (--from/--to: a date-windowed report covering only the review period)
halo policy   corroborate a chain against a declarative policy pack
              (per-rule pass / violation / evidence-gap; exit 1 violated, 3 nothing in scope)
halo serve    serve per-tenant reports over HTTP, access-scoped per customer
halo grant    designate a report recipient (email or domain)
halo viewers  list who has unlocked a gated report
halo anchor   witness a chain head, or --check completeness (exit 1 incomplete, 3 unwitnessed)
halo witness-serve  run a witness over HTTP: vendors anchor chain heads, viewers fetch checkpoints
halo demo     scaffold the full vendor demo (record -> witness -> gated report)
halo export   date-bounded evidence export: CSV + manifest tied to the chain head
halo sample   emit a valid example log
halo hash     canonical sha256 of a JSON value
halo hook     Claude Code PostToolUse hook
```

## Integrity model

To compute a record's hash: take the record excluding `integrity.hash`, with `integrity.prev_hash` set to the previous record's hash; canonicalize with RFC 8785 (JSON Canonicalization Scheme); SHA-256 the bytes. The first record's `prev_hash` is 64 zeros. Verification recomputes every hash and checks every link. No secret required; that is the point.

Think you can tamper with a chain without the verifier noticing? [Attempts and results live here](https://github.com/bkuan001/halo-record/discussions/2).

Full field reference: [`halo-record.schema.json`](src/halo_record/halo-record.schema.json).

## TypeScript

The same recorder ships for Node: [`halo-record-ts`](https://github.com/bkuan001/halo-record-ts). Same chain format, same witness protocol. Records written in either language verify with either verifier.

## Contributing

Issues, discussions, and pull requests welcome — see [CONTRIBUTING.md](https://github.com/bkuan001/halo-record/blob/main/CONTRIBUTING.md) for the ground rules (short version: tests required, small PRs, schema changes get discussed first).

## License

Apache-2.0
