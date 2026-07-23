# halo-record — Architectural Limits

What halo-record does not do, by design. These are boundaries, documented so a
reviewer can evaluate the system honestly. Each one states what holds, what
does not, and what to say when an assessor asks.

---

## 1. A self-held chain proves integrity, not completeness

The hash chain proves no record was edited, reordered, or truncated *relative
to a head you already know*. It cannot prove the operator never wrote a record
in the first place, or did not delete recent records and re-seal a shorter
chain before anyone saw it.

**What closes it:** a witness outside the operator's control holding periodic
checkpoints (a record count and a head hash). The witness protocol ships in
this repo (`halo witness-serve`, `halo anchor`); a hosted, recognized witness
is the piece still being built.

**What you say to a reviewer:** "The chain is tamper-evident against everyone
except the party that operates the recorder. Completeness against the operator
requires the external witness, and until one holds checkpoints for this chain,
the report says exactly that."

---

## 2. Records are deliberately not signed

There is no per-record signature. This is a design decision, not an omission:
a signature proves *the keyholder* produced the record, and when the keyholder
is the party under review, they can re-sign a rewritten history end to end.
A signature also means verification requires trusting key custody. The chain
plus an external witness makes rewriting *visible* without requiring anyone to
hold or trust a secret — anyone can re-verify with open code.

**What you say to a reviewer:** "Signatures authenticate an author; our threat
model's adversary *is* the author. The control that binds history is the
witnessed checkpoint, not a self-held key."

---

## 3. Capture depth is tiered, and the tier is disclosed

**Captured** means the recorder observed the call at the boundary as it
happened. **Ingested** means the record was built from telemetry the operator
already emits (a gateway, tracing store, or OTel span) — real and anchorable,
but the witness attests "this is the stream you sent me," not "I watched it
happen." Reports label every action's tier and never flatten the distinction.

**What you say to a reviewer:** "Ingested records inherit the trustworthiness
of the system that produced them; captured records inherit the recorder's.
The report tells you which is which."

---

## 4. Capture completeness is bounded by instrumentation

The recorder writes what flows through the instrumented paths (`trace()`, the
integrations, the hook). An agent acting through an uninstrumented side channel
produces no record, and no record system can self-certify that its coverage of
the runtime is total.

**What you say to a reviewer:** "The record covers the declared capture
surface. Verifying that the surface matches the deployment is a review
question about the integration, and the integration is open code."

---

## 5. Agent identity is declared, not cryptographically attested

The `agent` block (id, name, version, model) is supplied by integration code.
Version-binding makes "which build did this" answerable by column, but the
declaration itself is not bound to a runtime identity. Binding a record to a
specific attested process requires runtime attestation infrastructure (TEEs,
SPIFFE/SPIRE-class systems) outside this library's scope.

---

## 6. Redaction is best-effort, not a guarantee

Raw tool arguments are hashed, never stored. The summary layer is scrubbed by
provider-specific patterns plus an entropy catch-all — defense in depth, not a
proof. A novel secret format can land in a summary. If you find a path that
does, that is a vulnerability report we want (see SECURITY.md).

The same bound applies to `data.pii_types`: it is derived from the scanner's
*named* personal-data categories (email, ssn, credit_card, phone, iban), so it
is a floor, not a census. Free-form personal data with no fixed shape — a
person's name, a postal address — has no reliable pattern and will not appear
in `pii_types` or be masked in a summary. A policy rule over `pii_types` (e.g.
"no SSN crosses the boundary") therefore corroborates over what the scanner
catches; it is not a comprehensive PII gate.

**What you say to a reviewer:** "PII detection is by named pattern. Categories
we name, we catch and can gate on; unstructured PII is out of the scanner's
scope, and the report never implies otherwise."

---

## 7. The policy engine is evaluative, never enforcing

`halo policy` judges records after the fact against deterministic rules. It
does not intercept, block, or approve anything at runtime. If the agent
framework ignores a control, the verdict records the violation; it does not
prevent it. Enforcement belongs to the operator's runtime stack; evidence of
what happened belongs here.

---

## 8. Report access gating is a distribution control, not authentication

Gated Runtime Reports grant access by email domain. That is a "right audience"
control for sharing evidence with a counterparty; it is not an identity proof,
and it is not part of the integrity model. Verification of the records
themselves requires no access control at all — the math is public.

---

## 9. Single-writer chains

Each subject's chain assumes one recorder appending in order. Multi-writer or
distributed recording requires coordination this library does not provide.
Multi-agent *attribution* is supported (records carry the acting agent);
concurrent multi-process *writing* to one chain is not.

---

## 10. Principal and authorization are declared, not externally attested

The `principal` block (human_id / creator_id / service_account / role_scope)
and `action.authorization.decision` are supplied by integration code, the same
as the `agent` block (§5). They are sealed into the hash chain, so they are
tamper-evident *after the fact* — no one can rewrite who the agent said it acted
for without breaking the chain. But the declaration itself is not bound to an
authenticated session or IdP token: the record attests "the agent asserted this
principal / this authorization decision," not "an identity provider proved it."

**What you say to a reviewer:** "Attribution is as strong as the integration
that supplies it, sealed so it cannot be altered later. Binding it to an
authenticated session is an integration question — the hook can carry a signed
session assertion — not a property the chain invents on its own. Treat it as
corroborating evidence for who acted, not cryptographic proof of authorization."

---

## 11. Delegation links are asserted; verification reports their resolution

`parent_id` records which action caused this one (sub-agent / delegation
chains). `halo verify` checks referential integrity: for a complete chain it
reports whether every `parent_id` resolves to a record that appeared earlier,
and surfaces any that do not. It does not fail verification on an unresolved
link, because a windowed export legitimately references parents outside the
window — so an orphan is reported, not treated as tampering.

**What you say to a reviewer:** "Over a complete chain, 'all parent links
resolved' is a checkable property, not a claim you take on faith. On a windowed
export, unresolved parents are expected and the verifier says so."
