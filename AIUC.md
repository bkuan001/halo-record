# halo-record × AIUC-1: an evidence mapping

This document maps the evidence classes a Halo Runtime Record produces to the control framework published at [aiuc-1.com](https://aiuc-1.com). It is a reference for vendors preparing for an AIUC-1 audit and for auditors evaluating what a Runtime Record export can support.

Three things this document is not:

- **Not an affiliation.** halo-record is an independent open-source project. It is not associated with, endorsed by, or certified under AIUC-1. Control names and IDs below reference AIUC's published framework.
- **Not a compliance claim.** Whether any evidence is sufficient for any control in any deployment is a determination for the certifying auditor. This maps what the record *contains*, not what an audit will *accept*.
- **Not a completeness claim.** A Runtime Record documents what flowed through the recorder while it was running. See [LIMITS.md](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md) for the capture boundary.

**Legend** — *Direct*: the record or its tooling is itself the evidence class the sub-control names. *Contributing*: the record supplies part of the evidence; the operator supplies the rest (the system, workflow, or documentation around it). *Out of scope*: halo-record does not address this by design.

---

## Direct evidence

### E015 — Log AI system activity (Accountability · Mandatory)

The closest-fit control in the standard. Sub-control by sub-control:

| Sub-control | Requirement (abridged) | What the record provides |
|---|---|---|
| **E015.1** Logging Implementation | inputs, processing steps, outputs, metadata | Each record carries `action.input` (summary + hash), `action.type`/`action.tool`, `outcome` (status, summary, hash), `ts`, `session_id`, `agent` (id, version, model), `principal`. |
| **E015.2** AI Agent Logging | provenance metadata, tool call parameters/results, delegation records, approval events, reasoning traces where available | Provenance: `agent.*`, `mcp.host/client/server`. Tool calls: `action.tool` + input/outcome. Delegation: `parent_id` + `session_id` chain records into execution trees. Approval events: `action.authorization.decision` (`allowed` / `denied` / `human_approved`) + `approver` identity. **Gap, stated plainly: reasoning traces are not captured.** |
| **E015.3** Log Storage | retention policies, access controls, sanitation (incl. PII-masking) | Sanitation: PII is flagged (`data.pii_types`) and masked in the record — raw identifiers don't enter the chain. Each record carries `retention.policy` / `retention.expires` and `jurisdiction` fields. **Boundary: enforcement of retention (automated deletion) happens in the operator's storage layer, not in halo-record.** |
| **E015.4** Log Integrity Protection | logs cannot be modified post-creation and are **independently verifiable**; named implementations include **cryptographic hashing of entries**, WORM, append-only storage | This is the core of the format: every record is SHA-256 hash-chained over an RFC 8785 canonical form (`integrity.prev_hash` / `integrity.hash`), with optional ECDSA-P256/Ed25519 signatures. Verification requires no trust in the producer: the dependency-free verifier re-computes the chain from the file alone, and anyone — customer, auditor, insurer — can run it. |

### D003.3 — Tool call log (under D003, Restrict unsafe tool calls · Reliability)

The sub-control asks for tracked tool calls capturing the originating MCP server, tool name, input parameters, and timestamps. A Runtime Record captures each of these per call: `mcp.server`, `action.tool`, input summary + hash, `ts` — sealed into the chain rather than sitting in a mutable log.

*Note the boundary within D003: the record evidences the **log** of tool calls (D003.3). The authorization gate (D003.1) and rate limits (D003.2) are enforcement controls the operator implements elsewhere; the record can show their outcomes (`denied` decisions) but is not the gate.*

---

## Contributing evidence

Controls where the record supplies the log-shaped half of the evidence and the operator supplies the system around it:

| Control | What the sub-control asks for | The record's contribution |
|---|---|---|
| **D003.4** Human-approval workflows | human confirmation for high-risk tool operations | Sealed record of each approval event: `decision: human_approved` + `approver` identity, in-chain, per action. The workflow tooling itself is the operator's. |
| **D003.5** Tool call log reviews | periodic review of tool usage patterns | Dated CSV exports (with chain-tied `csv_sha256` manifest) give reviewers a verifiable dataset covering the review period. The review process and its documentation are the operator's. |
| **B002.2** Adversarial incident logs | incident logs with timestamps and user/session context | Records carry `threats`, `findings`, `severity`, session context, and timestamps. Incident management (tickets, runbooks, escalation) is the operator's. |
| **B005.4** Input filtering logs | flagged-input logging with privacy-conscious metadata and audit trail | Filter events recorded as actions inherit the chain's integrity and the record's PII-masking. The filter itself is the operator's. |
| **B006.2** Agent security monitoring | logs of agent service calls; example logs demonstrating boundary violations | `network` / `read` / `write` / `tool_call` actions with `denied` outcomes are exactly such example logs. Alerting and dashboards are the operator's. |
| **C004.2** Out-of-scope attempt logs | logs of out-of-scope attempts with frequency data | Denied/refused actions are recordable events; exports give frequency data over a window. Boundary definitions and their updates are the operator's. |
| **C008.1** AI risk monitoring | behavior trace logs, prompt-response logging | The hash-chained session is a behavior trace by construction. Sampling programs, dashboards, and evaluation schedules are the operator's. |
| **A004.4** IP disclosure monitoring | logs/audit trails for outputs touching confidential sources | `read`/`write` actions with authority context (`authority.refs`, workspace hashes) form the audit-trail half. Review queues are the operator's. |
| **A006.1** PII detection & filtering | log redaction configuration, structured logging with PII isolation | The record's masked-by-default design (`data.pii_types` flags, masked values in-chain) is the structured-logging-with-PII-isolation half. Output filtering is the operator's. |
| **E009.1** Monitor third-party access | logs or audit trail of third-party access to AI systems | Where third-party tools/servers act through the agent, `mcp.*` + action records form a sealed access trail. |

---

## Out of scope, by design

halo-record is a recorder and a verifier. It produces evidence that actions occurred as recorded; it does not enforce, filter, test, or document. That excludes, deliberately:

- **Written policies and documentation controls** — failure plans (E001–E003), accountability assignment (E004), data-storage documentation (E005), vendor due diligence (E006), process reviews (E008), acceptable-use policy (E010), processing locations (E011), regulatory documentation (E012), QMS (E013), disclosure mechanisms (E016), transparency policy (E017).
- **Enforcement gates** — input/output filtering (B005, C003–C006), tool authorization and rate limits (D003.1/.2), access controls (B007), endpoint protection (B004), deployment-environment security (B008).
- **Testing** — adversarial, harmful-output, out-of-scope, hallucination, and tool-call testing, first- or third-party (B001, C002, C010–C012, D002, D004, F001–F002).

An audit needs all of these. The record's role is narrower: when those controls act — a filter blocks, a human approves, a tool executes — the record is the tamper-evident account of what happened.

---

## One record, several frameworks

AIUC-1's own published crosswalk for E015 maps the same evidence surface to: **ISO/IEC 42001** A.6.2.8 (event-log recording) · **NIST AI RMF** MEASURE 2.4 & 2.8 · **EU AI Act** Articles 12 & 19 (record-keeping; automatically generated logs) · **MITRE ATLAS** AML-M0024 (AI telemetry logging) · **CSA AICM** LOG-family controls · **OWASP Agentic Top 10** ASI06–ASI10. A vendor producing Runtime Records for an AIUC-1 audit is accumulating the same class of evidence those frameworks ask for.

---

## Known gaps

Stated here so nobody discovers them mid-audit: **reasoning traces** (E015.2 names them "where available"; the record does not capture them today) and **retention enforcement** (the record carries retention fields; automated deletion lives in the operator's storage layer). If either matters for your engagement, say so — the roadmap is demand-driven: bkuan001@gmail.com.
