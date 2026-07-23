# halo-record × AARM

[AARM](https://aarm.dev) (Autonomous Action Runtime Management) is an open specification — authored at Vanta, donated to the Cloud Security Alliance — that defines a system category for securing AI-agent actions at runtime: intercept an action, evaluate it against policy, enforce a decision, and **record a tamper-evident receipt** of what happened.

halo-record implements the **receipt** half of that spec. It is record-only by design — it does not intercept or enforce — so it is not a complete AARM system on its own. It is the evidence layer: pair it with a policy/enforcement gateway for a full AARM deployment, and halo-record produces the receipts that gateway is required to emit.

## AARM receipt requirements → halo-record fields

AARM's **R5** ("tamper-evident action receipt") requires each receipt to include, at minimum, the original action, the decision, the timestamp, and the policy context used in evaluation, and to be verifiable against unauthorized modification. **R6** requires each receipt to be cryptographically bound to an agent identity, with the binding verifiable and uniquely identifying the agent that acted.

| AARM receipt requirement | halo-record field |
|---|---|
| Original action (R5) | `action` — `type`, `category`, `tool`, `input.summary` + `input.hash` |
| The decision (R5) | `action.authorization.decision` — `allowed` / `denied` / `human_approved` |
| Timestamp (R5) | `ts` — RFC 3339 UTC |
| Policy context used in evaluation (R5) | `framework_tags`, `action.authorization.scope`, `findings`, `threats` |
| Verifiable against modification (R5) | `integrity` — SHA-256 over the RFC 8785 canonical form |
| Cryptographically bound to agent identity (R6) | The `agent` block (`id`, `name`, `version`, `model`) is sealed into every record's SHA-256 hash — so the acting agent's identity is **cryptographically bound and verifiable**: it cannot be altered without breaking the chain. The open half of R6 is *uniqueness* — those `agent` values are integration-supplied (self-asserted), not bound to an authenticated runtime identity. For deployments that want signature-level non-repudiation on top, the schema reserves a `signature` block (ECDSA-P256 / Ed25519, `key_id`); asymmetric signing sits deliberately outside the zero-dependency core — pair the recorder with your signing infrastructure. |

Requirement IDs follow AARM v1.0; [aarm.dev/spec](https://aarm.dev/spec) is the authoritative text.

## What halo-record adds on top

AARM requires each receipt to be *individually* tamper-evident. halo-record goes two steps further, and both are the point of the project:

- **Chain-linking.** Receipts are not just individually sealed; each carries the hash of the one before it (`integrity.prev_hash`). Edit or drop any record and every link after it breaks — so the *sequence* is tamper-evident, not only each receipt. That is the difference between "nothing was edited" and "nothing was reordered or removed."
- **An independent witness.** AARM receipts are produced and held by the operator's own runtime system. That proves integrity, never completeness — an operator can simply decline to write the inconvenient record. halo-record adds a witness: a party outside the operator holding a periodic count and head-hash of the chain, so a customer can verify *completeness* rather than take the operator's word. The receipt requirements do not define this layer; it is where independence comes from. See [Integrity vs. completeness](README.md#integrity-vs-completeness-read-this-part).

AARM defines the receipt. halo-record produces one, chains it, and lets someone outside the vendor vouch for it.
