# halo-record × Agentic Trust Controls

[Agentic Trust Controls](https://trustcontrols.ai) (ATC) is an open, community-built control set that extends ISO 27001 and ISO 42001 with controls written specifically for agentic AI. It is organized as two baselines: a **Developer baseline** for teams building agents, and a **User baseline** for teams deploying agents built by others.

halo-record is an evidence layer, so it maps to the ATC the way evidence maps to any control set: it does not make an organization "ATC compliant," it produces the runtime records several ATC controls call for — and gives whoever reviews them something verifiable to hold.

## ATC controls → what halo-record provides

| ATC control | What halo-record provides |
|---|---|
| **RBM-03** Tamper-evident action logging | The core of the project. Every consequential action is one record — what was done (`action.type`, `action.tool`, `action.input` summary + hash), under whose authority (`principal`, `action.authorization`, `authority`), on what input — sealed by SHA-256 over the RFC 8785 canonical form and chained to the record before it (`integrity.prev_hash`), so edits, reordering, and deletions break the chain visibly. `halo verify` checks a log offline, without trusting the producer. |
| **AID-05** Authority attestation at execution | The attestation content, written into the same tamper-evident log rather than kept as a separate mutable record: acting identity (`agent`: id, name, version, model), originating principal (`principal`), granted authority (`action.authorization`: decision, scope, approver; `authority` snapshot of the governing rules), and execution context (`session_id`, `parent_id`, `mcp`). |
| **MEM-03** Sensitive data exclusion from memory and logs (logging clause) | Records carry summaries and content hashes, not payloads; hash-only mode (`HALO_HASH_ONLY=1`) drops summaries entirely. The chain proves what happened without persisting the sensitive content itself. |
| **RBM-01** Behavioral telemetry generation | The record stream doubles as security-relevant telemetry — tool use, authorization decisions, outcomes, errors — in a reviewable, investigation-ready form. (halo-record is an evidence layer, not an observability product; pair it with your existing monitoring for dashboards and alerting.) |
| **RBM-07** Telemetry review and SOC integration (User baseline) | `halo export` produces a date-bounded CSV plus a manifest tied to the chain head, for routing agent evidence into existing review and incident processes. |
| **SCP-04** Vendor agent security review at procurement (User baseline) | The reviewing side of the same records: a deploying organization can ask an agent vendor for a Runtime Report backed by a verifiable chain, and check it, instead of accepting screenshots and prose. |

Mappings reflect the ATC catalog as of July 2026; the set is in early access and evolving.

## What halo-record adds beyond the catalog

The ATC's evidence controls, like most control sets today, place the records with the party that produced them. That proves **integrity** — nothing was edited after the fact. It cannot prove **completeness** — a producer can decline to write the inconvenient record, or re-seal a trimmed chain, and every internal check still passes.

halo-record adds the layer for the parties on the other side of that trust boundary: an **independent witness** holding periodic fingerprints of the chain (a count and a head hash, nothing else), so a customer, assessor, or regulator can verify a producer's records are complete — not just internally consistent — without taking the producer's word for it. See [Integrity vs. completeness](README.md#integrity-vs-completeness-read-this-part).

The catalog defines what to record. halo-record records it, seals it, and lets someone outside the producer vouch for it.
