# halo-record × CSA AI Controls Matrix (AICM): an evidence mapping

This document maps the evidence a Halo Runtime Record produces to the Cloud Security Alliance's [AI Controls Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) (AICM v1.1, June 2026 — 247 control objectives across 18 domains), the controls framework behind CSA's [STAR for AI](https://cloudsecurityalliance.org/star/ai/) program. Control text is quoted from CSA's [machine-readable AICM bundle](https://cloudsecurityalliance.org/download/artifacts/aicm-machine-readable-bundle-json-yaml-oscal) (JSON/YAML/OSCAL), so every quote below is checkable at source.

Three things this document is not:

- **Not an affiliation.** halo-record is an independent open-source project. It is not associated with, endorsed by, or assessed under CSA, AICM, or STAR for AI. Control IDs and text below reference CSA's published matrix.
- **Not a compliance claim.** Whether any evidence satisfies any control in any deployment is a determination for the assessor. This maps what the record *contains*, not what an assessment will *accept*.
- **Not a completeness claim.** A Runtime Record documents what flowed through the recorder while it was running. See [LIMITS.md](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md) for the capture boundary.

**Legend** — *Direct*: the record or its tooling is itself the evidence class the control names. *Contributing*: the record supplies part of the evidence; the operator supplies the rest. Everything else in the matrix — 18 domains of organizational, cryptographic, supply-chain, and personnel controls — is the operator's, by design.

---

## Direct evidence — the LOG domain

AICM's Logging and Monitoring domain (16 controls) is where a Runtime Record lives. The closest-fit controls (LOG-10, the protection control, sits under Contributing below — the chain supplies detection, not the prevention-and-access half the control's verb asks for):

| Control | Requirement (quoted/abridged) | What the record provides |
|---|---|---|
| **LOG-09** Log Records | "Generate audit records containing relevant security information." | Each record carries `ts`, `session_id`, `agent` (id, version, model), `principal`, `action.type`/`action.tool`, input summary + hash, `outcome`, and — where the integration supplies them — `threats`, `findings`, `severity`, and `action.authorization.decision`. |
| **LOG-15** Input Monitoring | "Log and monitor all input events (content and metadata) to enable auditing and reporting on the usage of AI models." | The logging half: action inputs are recorded as summary + hash with metadata (timestamp, session, agent, principal, MCP context) and sealed into the chain. Pattern-matched PII is masked before sealing — best-effort, not a guarantee ([LIMITS.md §6](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). "All input events" is a population claim the chain cannot make about itself: the chain proves the integrity of what was captured; completeness of capture is bounded by instrumentation ([LIMITS.md §4](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). Monitoring/alerting on the stream is the operator's. |
| **LOG-16** Output Monitoring | Same as LOG-15, for output events. | The logging half, same bounds as LOG-15: `outcome` (status, summary, hash) per action, sealed in-chain. |

## Contributing evidence

| Control | What it asks for | The record's contribution |
|---|---|---|
| **LOG-10** Audit Records Protection | "Protect audit records from unauthorized access, modification, and deletion." | Contributing, not direct, by this document's own legend: the chain covers the modification-and-deletion half as *detection* — every record is SHA-256 hash-chained over a canonical form (RFC 8785, a rule set that makes the same data always hash the same way), so modification, deletion, or reordering is detectable by anyone who runs the open verifier against a verified head (the most recent record's hash, saved by a reader or held by a witness). Tamper-evident, not tamper-proof: *prevention* of modification and the entire access-control half are the operator's storage layer, and detecting an operator who rewrites and re-hashes the whole chain ("re-sealing") requires a checkpoint held outside the operator — by the relying party or a witness ([LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). |
| **LOG-02** Audit Logs Protection | "Ensure the security and retention of audit logs." | Integrity comes from the chain. Retention, stated flatly: the reference implementation has no retention or expiry capability — the schema reserves `retention.policy` / `retention.expires` as documentation fields for the operator to populate, and enforcement lives entirely in the operator's storage layer ([RETENTION.md](https://github.com/bkuan001/halo-record/blob/main/RETENTION.md), [LIMITS.md §13](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). |
| **LOG-04** Audit Log Access | "Restrict audit log access to authorized identities and maintain records of that access." | Access restriction is the operator's storage layer. Where log access itself is routed through an agent tool, it is recordable as an action like any other. |
| **LOG-05** Log Correlation/Monitoring | Correlate and monitor logs for anomalies. | The record is the correlatable dataset — chained sessions, `parent_id` execution trees, dated CSV exports with a chain-tied manifest. The correlation tooling is the operator's. |
| **LOG-07** Logging Scope | Define what is logged; review the scope. | The capture surface is explicit and documented ([LIMITS.md §4](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)): what the instrumented paths saw, at a disclosed capture tier. The scope definition and its review are the operator's. |

## A distinction worth naming: artifact integrity vs. behavior integrity

AICM's cryptographic-integrity controls for AI live in the Model Security domain — **MDS-08** (cryptographic hashes of model checkpoints to detect unauthorized modification) and **MDS-09** (model signing for provenance). Those protect the *artifact*: the weights you deploy are the weights you trained. A Runtime Record protects the *behavior*: what the deployed system actually did, hash-chained per action. The two are complementary halves of one question — "is this the model, and is this what it did?" — and neither substitutes for the other.

---

## One record, several frameworks

CSA's own AICM v1.1 crosswalk maps its LOG-family controls to **AIUC-1 E015** ("Log AI system activity") — the control mapped sub-control-by-sub-control in [AIUC.md](https://github.com/bkuan001/halo-record/blob/main/AIUC.md). AICM also publishes mappings to ISO/IEC 42001, ISO 27001, NIST AI RMF, and the EU AI Act. A vendor producing Runtime Records is accumulating one evidence class that these frameworks reach by different names. Within STAR for AI, that evidence is supporting material — Level 1 is a self-assessment against the AI-CAIQ, Level 2 adds a third-party ISO/IEC 42001 certification; neither level's assessment is something a record can perform.

## Boundaries

- **Tamper-*evident*, not immutable.** LOG-10 says "protect from modification and deletion"; the chain's precise property is that modification and deletion are *detectable* relative to a verified head, by anyone, without trusting the operator. Prevention is a storage property the operator supplies.
- **Integrity is not completeness.** A record the operator holds proves nothing was *edited*, never that nothing was *omitted*. Completeness against the operator requires the external witness — see [Integrity vs. completeness](README.md#integrity-vs-completeness-read-this-part) and [LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md).
- **The record does not monitor.** LOG-05/15/16 pair logging with monitoring; the record is the sealed dataset monitoring runs over, not the alerting system.

This is a community mapping against CSA's published v1.1 control text, not a CSA artifact; corrections welcome.
