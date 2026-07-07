# halo-record

Tamper-evident **runtime records for AI agents**: the audit trail the vendor runs but cannot edit.

Every action your agent takes (tool calls, model calls, data access, approvals) becomes one record in an append-only, hash-chained log. Any party can verify the log was never altered, without trusting whoever produced it. When a customer's security team asks "what did your agent do with our data?", you hand them a link instead of a paragraph. Security reviews already ask AI questions next to the SOC 2 checklist, and today a written assurance still passes. The bet behind this project is that it won't for long.

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

Add that to `~/.claude/settings.json` and records land in `~/.halo/audit.jsonl` (override with `$HALO_LOG`). Pure-orchestration tools that touch no data, network, or external state are skipped — the chain records trust-boundary actions, not thinking. Set `HALO_HASH_ONLY=1` to record content hashes without summaries. Then, the usual:

```
halo verify ~/.halo/audit.jsonl
halo report ~/.halo/audit.jsonl -o report.html
```

Any agent runtime that exposes a post-action hook can feed the same command — the hook reads one event as JSON on stdin and appends one record.

## Integrity vs. completeness (read this part)

A self-held chain proves **integrity**: nothing was edited or reordered after the fact. It cannot prove **completeness**: the operator of a recorder can delete the bad day and re-seal the chain, or never write a record at all, and the chain stays internally consistent.

Completeness requires a party outside the operator's control holding periodic fingerprints of the chain (a count and a head hash, nothing else). That is the witness:

```
halo anchor audit.jsonl witness.jsonl           # anchor a checkpoint to a local witness
halo anchor audit.jsonl witness.jsonl --check   # completeness verdict against it
```

Anyone can run a witness. A witness you run yourself proves integrity to *you*; proving completeness to *your customer* requires a witness they have reason to trust. The protocol is open either way.

A hosted, recognized witness is how this project will sustain itself. Early access: bkuan001@gmail.com.

## Where this sits in a compliance stack

halo-record is an evidence layer, not a certification. It produces the artifact that assessment frameworks keep asking for in different words:

- **Security questionnaires and SOC 2 reviews:** answer the AI sections with a verifiable Runtime Report instead of screenshots and prose.
- **AIUC-1:** continuous runtime evidence for agent-behavior requirements, instead of evidence reconstructed at audit time.
- **OWASP (GenAI Security Project):** the runtime evidence behind the agent-behavior risks in the OWASP Top 10 for LLM Applications and the Agentic Security Initiative — excessive agency, tool misuse, sensitive-information disclosure — recorded as what the agent actually did, with which tools and data.
- **AARM (CSA):** produces the tamper-evident action receipt AARM specifies (R5/R6) — chained and independently witnessed. halo-record is the receipt layer; pair it with an enforcement gateway for a full AARM system. See [`AARM.md`](AARM.md).
- **EU AI Act:** logging and record-keeping obligations for high-risk AI systems.
- **ISO 42001 / NIST AI RMF:** the operational evidence behind management-system controls.

None of this certifies anything by itself. It gives your assessor something verifiable to look at.

## CLI

```
halo verify   validate schema + hash chain (non-zero exit on failure; CI-friendly)
halo report   render a chain as a self-verifying HTML Runtime Report
halo serve    serve per-tenant reports over HTTP, access-scoped per customer
halo grant    designate a report recipient (email or domain)
halo anchor   witness a chain head, or --check completeness
halo demo     scaffold the full vendor demo (record -> witness -> gated report)
halo sample   emit a valid example log
halo hash     canonical sha256 of a JSON value
halo hook     Claude Code PostToolUse hook
```

## Integrity model

To compute a record's hash: take the record excluding `integrity.hash`, with `integrity.prev_hash` set to the previous record's hash; canonicalize with RFC 8785 (JSON Canonicalization Scheme); SHA-256 the bytes. The first record's `prev_hash` is 64 zeros. Verification recomputes every hash and checks every link. No secret required; that is the point.

Full field reference: [`halo-record.schema.json`](src/halo_record/halo-record.schema.json).

## TypeScript

The same recorder ships for Node: [`halo-record-ts`](https://github.com/bkuan001/halo-record-ts). Same chain format, same witness protocol. Records written in either language verify with either verifier.

## License

Apache-2.0
