# halo-record

Tamper-evident **runtime records for AI agents**: the audit trail the vendor runs but cannot edit.

Every action your agent takes (tool calls, model calls, data access, approvals) becomes one record in an append-structured, hash-chained log. Any party holding a checkpoint of the chain can verify the records behind it were never altered, without trusting whoever produced them. When a customer's security team asks "what did your agent do with our data?", you hand them a link instead of a paragraph. Security reviews already ask AI questions next to the SOC 2 checklist, and today a written assurance still passes. The bet behind this project is that it won't for long.

The record format is open and free to implement. This package is the reference implementation: recorder, verifier, witness client, and report server.

## Why you can trust this code

You are being asked to put a recorder inside your agent. You should not take that on faith:

- **Zero runtime dependencies.** Standard library only. `pip install halo-record` installs exactly one package.
- **No network calls**, except the witness, which is opt-in and receives only a record count and a chain fingerprint. Record contents never leave your infrastructure.
- **Raw inputs never enter a record.** Arguments are hashed and stored only as a redacted summary — never the raw value. Redaction is best-effort (regex over common secret and PII formats): treat it as defense-in-depth, not a guarantee.
- **Small enough to audit.** ~4,300 lines of Python. Read all of it in an afternoon.
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

Either one scaffolds a fictional support-agent vendor with two customers, witnesses the chains, serves their gated Runtime Reports, and opens the operator console in your browser. Then try the tamper test: delete a line from one of the `.jsonl` files and reload. The report catches it.

## Record your own agent

One line at the boundary:

```python
from halo import trace

agent = trace(run_my_agent, profile="my-agent", log="audit.jsonl")   # wraps your entrypoint; records every tool call to ./audit.jsonl
```

Without `log=`, records go to `~/.halo/my-agent.jsonl` (one chain per agent). Or use the adapter for what you already run (see the matrix below). Then render the report:

```
halo report audit.jsonl -o report.html    # one chain -> self-verifying HTML
halo serve ./records --port 8721          # all tenants, gated per customer
```

The quickstart ends when you are looking at your own agent's Runtime Report in a browser. If you got a JSONL file and no report, something is wrong: open an issue.

## Connect to what you already run

| Captured at the boundary | Ingested from existing telemetry |
|---|---|
| Native recorder (`from halo import trace`) | OpenTelemetry GenAI spans |
| MCP interceptor | LiteLLM callbacks |
| LangChain / LangGraph callback | Langfuse export |
| OpenAI Agents SDK hooks | Any gateway / reverse-proxy log |
| Claude Code / Claude Agent SDK hook | |

Every record carries a `source` tag, so the report discloses how each piece of evidence was collected. Captured and ingested records live in the same chain.

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

## Integrity vs. completeness (read this part)

Be precise about what each layer proves — because they are different claims, and the differences are the point:

A self-held chain proves **integrity relative to an established head**: given a chain head someone already holds, any edit, reordering, or deletion in the records behind it becomes detectable. By itself — before anyone outside the operator has seen a head — a chain proves internal consistency, not history: an operator could drop a record and re-seal, and the new file would verify. The chain becomes **historically committed** the moment its head leaves the operator's control.

That is the witness: a party outside the operator holding periodic fingerprints of the chain (a count and a head hash, nothing else). Checkpoints make rewriting committed history detectable, and a missed checkpoint is itself a visible event:

```
halo anchor audit.jsonl witness.jsonl           # anchor a checkpoint to a local witness
halo anchor audit.jsonl witness.jsonl --check   # completeness verdict against it
```

One more boundary, stated plainly: neither the chain nor the witness proves that every real-world action passed through the recorder. That is **capture completeness** — a property of where the recorder sits in the stack (native instrumentation, hooks, gateway ingestion), not of any hash. Records carry a `source` tag for exactly this reason.

| Claim | Self-held chain | + External checkpoints | + Trusted capture |
|---|---|---|---|
| Detect edits to an established artifact | ✔ | ✔ | ✔ |
| Detect rewriting of committed history | — | ✔ | ✔ |
| Detect missing/late checkpoints | — | ✔ (agreed cadence) | ✔ |
| Prove every action was recorded | — | — | depends on capture boundary |

Anyone can run a witness. A witness you run yourself commits history to *you*; committing it to *your customer* requires a witness they have reason to trust. The protocol is open either way.

A hosted, recognized witness is how this project will sustain itself. Early access: bkuan001@gmail.com.

## Where this sits in a compliance stack

halo-record is an evidence layer, not a certification. It produces the artifact that assessment frameworks keep asking for in different words:

- **Security questionnaires and SOC 2 reviews:** answer the AI sections with a verifiable Runtime Report instead of screenshots and prose.
- **AIUC-1:** produces the tamper-evident logging (E015.4) and full-execution-chain records with authorization events (E015.2) the standard's Accountability controls call for — continuous runtime evidence, not reconstructed at audit time.
- **OWASP (GenAI Security Project):** the runtime evidence behind the agent-behavior risks in the OWASP Top 10 for Agentic Applications 2026 and the LLM Top 10 — goal hijack, tool misuse, identity and privilege abuse — recorded as what the agent actually did, with which tools and data.
- **AARM (CSA):** produces the tamper-evident action receipt AARM specifies (R5/R6) — chained and independently witnessed. halo-record is the receipt layer; pair it with an enforcement gateway for a full AARM system. See [`AARM.md`](AARM.md).
- **Agentic Trust Controls:** the runtime records behind the ATC's evidence controls — tamper-evident action logging (RBM-03) and authority attestation (AID-05) in one chained record, with the witness layer beyond both. See [`ATC.md`](ATC.md).
- **EU AI Act:** logging and record-keeping obligations for high-risk AI systems.
- **ISO 42001 / NIST AI RMF:** the operational evidence behind management-system controls.

None of this certifies anything by itself. It gives your assessor something verifiable to look at.

## CLI

```
halo verify   validate schema + hash chain (non-zero exit on failure; CI-friendly)
halo report   render a chain as a self-verifying HTML Runtime Report
              (--from/--to: a date-windowed report covering only the review period)
halo serve    serve per-tenant reports over HTTP, access-scoped per customer
halo grant    designate a report recipient (email or domain)
halo anchor   witness a chain head, or --check completeness
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

Issues, discussions, and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules (short version: tests required, small PRs, schema changes get discussed first).

## License

Apache-2.0
