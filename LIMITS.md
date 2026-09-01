# halo-record — Architectural Limits

What halo-record does not do, by design. These are boundaries, documented so a
reviewer can evaluate the system honestly. Each one states what holds, what
does not, and what to say when an assessor asks.

---

## 1. A self-held chain proves integrity, not completeness

The hash chain proves no record was edited, reordered, or truncated *relative
to a head you already know*. It cannot prove the operator never wrote a record
in the first place, or did not remove records — from the tail or from anywhere
in the chain — and re-seal the remainder before anyone saw it. A re-sealed
chain verifies clean; only a checkpoint captured before the re-seal exposes it.

**What closes it:** a witness outside the operator's control holding periodic
checkpoints (a record count and a head hash). The witness protocol ships in
this repo (`halo witness-serve`, `halo anchor`); a hosted, recognized witness
is the piece still being built.

Checkpoints are unsigned. A checkpoint file presented to you *by the operator*
proves nothing — it can be rewritten in a few lines to match any re-sealed
chain. The closure only holds when you fetch the checkpoint from the witness
yourself, or hold your own copy captured earlier. Signed witness receipts are
deliberately outside the zero-dependency core; until they exist, treat any
relayed checkpoint as the operator's assertion.

For *time* specifically, `halo anchor --timestamp` attaches an external RFC 3161
timestamp to a checkpoint: a Timestamp Authority the operator does not control
signs the checkpoint's state hash, proving the chain reached that state **no
later than** the attested time. This bounds the *checkpoint*, not each record —
per-record `ts` fields stay self-asserted — and it proves time, not completeness
(the witness is still what proves nothing was dropped). The tool's own `--check`
confirms the token binds this chain state and reads its claimed time, but it does
**not** validate the TSA's signature; the token is a standard artifact, so trust
the time by verifying that signature yourself against a TSA you trust:
`openssl ts -verify -digest <tsa.digest> -in <token> -CAfile <tsa-ca>`
(base64-decode `tsa.token_b64` into `<token>` first; use a commercial TSA in
production).

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

The `authority` block is exempt from the redaction pass entirely: it is stored
exactly as the producer supplies it, and the hashes-and-refs convention is not
checked by any code path.

The same bound applies to `data.pii_types`: it is derived from the scanner's
*named* personal-data categories (email, ssn, credit_card, phone, iban), so it
is a floor, not a census. Within a category the coverage is by shape: cards and
IBANs are caught in their spaced/hyphenated printed forms (cards Luhn-checked);
SSNs are caught in delimited form (`123-45-6789`, `123 45 6789`), but an
undelimited nine-digit run is deliberately not classified as an SSN — it is
indistinguishable from any other nine-digit identifier, and treating every one
as PII would redact ordinary IDs. Free-form personal data with no fixed shape — a
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

What unserialized concurrent appends look like in practice: two processes read
the same chain head and both write, forking the chain at that record (two
records claiming the same predecessor). Verification names the first affected
record (`prev_hash` / `hash` mismatch) and reports everything after it, once,
as a tail that can no longer be proven to descend from the pre-break chain —
the damage is detectable and permanent, and the verifier does not resume from
a record's self-declared hash to grade later records individually. A later
span can still be evaluated on its own terms with a windowed report. From the
chain alone, a fork from a write race and a deliberate edit present
identically: verification reports the break, not its cause.

Both packages' `Recorder` classes serialize their own appends across
processes, each with a sidecar lock held over the read-head-then-append
sequence: the Python package takes a POSIX `flock` on a `<chain>.lock` file
(on platforms without `flock`, appends are serialized per-process only); the
TypeScript package takes a `<chain>.lock.d` lock directory (atomic `mkdir`,
all platforms). Writers that share a `Recorder` path are covered — including
`halo hook`, which appends through `Recorder`. The two packages' lock
mechanisms do not interoperate: writers in both languages sharing one chain
should write per-process chains instead. Anything that writes the chain file
directly — a hand-rolled hook, a log shipper, parallel workers — must hold an
equivalent exclusive lock across the read-head-then-append sequence (e.g.
`flock` on the chain's `.lock` sidecar, the same lock the Python `Recorder`
takes), or write to per-process chains (one file per worker, each
independently verifiable).

---

## 10. Principal and authorization are declared, not externally attested

The `principal` block (human_id / creator_id / service_account / role_scope)
and `action.authorization.decision` are supplied by integration code, the same
as the `agent` block (§5). They are sealed into the hash chain, so they are
tamper-evident *after the fact* — no one can rewrite who the agent said it acted
for without breaking the chain. But the declaration itself is not bound to an
authenticated session or IdP token: the record attests "the agent asserted this
principal / this authorization decision," not "an identity provider proved it."
The optional `verification` block is the same kind of statement — see §11.

**What you say to a reviewer:** "Attribution is as strong as the integration
that supplies it, sealed so it cannot be altered later. Binding it to an
authenticated session is an integration question — the hook can carry a signed
session assertion — not a property the chain invents on its own. Treat it as
corroborating evidence for who acted, not cryptographic proof of authorization."

---

## 11. Verification status is the gate's report, not Halo's finding

The optional `verification` block records what an upstream verification or
policy gate said about the action at the moment it ran, as supplied by the
operator's integration code — the same trust posture as `principal` and the
`agent` block (§5, §10). Sealing makes the claim tamper-evident after the
fact: no one can rewrite what the gate was said to have decided without
breaking the chain. But nothing in Halo ran the check, so the seal does not
prove the check occurred, that the verdict was correct, or that a `blocked`
action did not execute. And `policy_ref` is only as strong as its resolution:
a content hash of a retained ruleset can be produced and compared; an
unresolvable label cannot.

**What you say to a reviewer:** "`verification.status` is the named gate's own
report of its decision, written by the operator's integration and sealed so it
cannot be altered afterward. Halo records it; nothing in Halo confirms it.
Treat it as corroborating evidence that a control was operating — reliance
requires producing the ruleset matching `policy_ref` and independent evidence
the verifier was deployed as claimed."

---

## 12. Delegation links are asserted; verification reports their resolution

`parent_id` records which action caused this one (sub-agent / delegation
chains). `halo verify` checks referential integrity: for a complete chain it
reports whether every `parent_id` resolves to a record that appeared earlier,
and surfaces any that do not. It does not fail verification on an unresolved
link, because a windowed export legitimately references parents outside the
window — so an orphan is reported, not treated as tampering.

**What you say to a reviewer:** "Over a complete chain, 'all parent links
resolved' is a checkable property, not a claim you take on faith. On a windowed
export, unresolved parents are expected and the verifier says so."

---

## 13. Personal data and erasure

**If someone asks to be deleted — the short version.** Nothing can be removed from
this log. If a person's details were written into it, they stay there permanently.
The only workable approach is to keep personal data out of the log from the start:
store a meaningless reference code, and keep the code-to-person list in an ordinary
database you can delete from. Three things defeat that and you must check all three.
Unstructured details like names and street addresses are never masked and land in
the log as written. One field in every record normally holds a person's work login,
usually an email address — check whether that person is one of your staff or one of
your customers, because that decides whether any of this applies to you. And if the
agent's inputs are things an outsider could guess, like an email address or an
account number, the stored fingerprint of those inputs can still be matched back to
a person even after you delete your list.

The log is also not the only copy. The same text is carried into the exported CSV
you upload to a GRC platform, and into any Runtime Report you share with a
counterparty — and report access is granted by email domain, which section 8
explains is not an identity proof. One record per tenant is your job, not the
tool's: `halo report` renders whatever chain you point it at, so a file holding
more than one tenant produces a single report carrying all of them, titled with
just one. Route each tenant to its own chain and check that routing before sharing
anything. There is no retention or expiry capability at all: records live as long
as your storage keeps them.

---

The chain is append-only and hash-chained. Removing or editing a record breaks
verification for every record after it. That is the point of the design — and it
means anything sealed into a record is, for practical purposes, permanent.

**More than one field carries caller-supplied text.** `subject` is the obvious one,
and it is meant for the tenant *organization* an action serves — not for a natural
person. But it is not the only door. Everything in this table is sealed verbatim.
The table is a starting point, not a closed inventory: any caller-supplied string
can carry personal data, and only the summaries are scanned at all.

| Field | How it goes wrong |
|---|---|
| `principal.human_id` / `creator_id` / `role_scope` | names the person the action ran on behalf of — teams put a work login here, which is usually an email address |
| `action.authorization.approver` / `scope` / `decision` | the approving person's name or login, and values built from one |
| `outcome.*` (keys other than `summary`) | passed through untouched and never scanned — a result field like `customer` or `address` seals a person's details permanently |
| `session_id`, `parent_id` | free-form; often built by joining a user identifier to a date |
| `agent.*`, `source.*`, `authority.*` | free-form labels — a laptop, an assistant, or a runbook named after a customer |
| `action.tool` | a tool name built from the thing it acts on |
| `threats[].type` / `.ref` | ticket references and notes copied from an upstream detector |
| `data.*` | any key you add beyond `region` / `purpose` / `cross_region` |
| `action.input.summary`, `outcome.summary` | redacted best-effort only — and per section 6 a **name or postal address has no reliable pattern, is not detected, and is not masked** |
| `findings[].type` / `.sample` | masked fragments *when the scanner produced them* — a masked email keeps its full domain and an SSN keeps its last four. Findings you supply yourself are stored exactly as given, unmasked |

Note that `summaries=False` drops the human-readable summaries but does **not**
empty the record of payload-derived text: `findings[].sample` and `data.pii_types`
are computed before summaries are dropped and survive.

**The stored fingerprint can confirm a guess.** `action.input.hash` is an unsalted
SHA-256 over the canonical tool arguments. Where those arguments come from a small
or guessable set — an email address, a customer number — anyone who can guess a
value can confirm it by hashing their guess and comparing. Deleting an external
mapping does not sever that link, and the masked findings above narrow the guessing
down further. Treat the input hash as pseudonymous data, not as a value that
reveals nothing. There is no salted or keyed option today.

**The pattern that works, and its actual scope:** put a stable pseudonymous
identifier in the chain, keep the mapping to an individual in a system you control
and can delete from, and keep personal data out of every field in the table above —
not just `subject`. An erasure request is then satisfied by deleting the mapping.
No library setting enforces this; it is a discipline in how you call the recorder.

Two things this is not:

- **It is not anonymization.** A pseudonymous identifier is still personal data
  under most privacy regimes. This makes erasure *tractable*; it does not put the
  data outside the regime, and halo-record makes no compliance claim.
- **It is not a retention policy.** There is no built-in expiry or pruning today,
  so retention is whatever your storage does. Dropping old records at anchored
  checkpoints is possible in principle but is not implemented.

Where a record must be kept because a regulation requires the log, that obligation
covers keeping *the record*. It does not license keeping more identifying detail
inside the record than the purpose needs.

**What to ask the vendor** (this part is for the reviewer, not the engineer):

1. *Which fields do you write personal data into?* Ask for the table above,
   answered row by row, then ask to see twenty real records. "Only the subject
   field" is not a sufficient answer.
2. *Whose login goes in the `principal` field — your staff, or your customers?*
   If it is customers, personal data is in every record by default.
3. *Could an outsider guess your tool-call inputs?* Emails, account numbers or
   anything from a small set stay matchable no matter what else has been deleted.
   "They are random identifiers" is a good answer; "they are customer emails" is a
   finding.
4. *Where does the code-to-person list live, and can you demonstrate deleting from
   it?* Ask to watch a deletion.
5. *What is your retention period, given the tool provides none?* Any answer that
   is not a specific period, applied automatically, is a finding.
6. *Where else does this data go, and who can currently open a Runtime Report?*
   Named systems and named recipients — access is by email domain, so ask whether
   they can revoke one named person.
7. *Can you answer an access request as well as a deletion one?* Ask them to
   produce everything they hold on one individual, across every field above.

A vendor who says "identifiers in the chain are pseudonymous" without addressing
`principal`, the summaries, and the input fingerprint has not answered the question.

## 14. Numeric values are canonicalized to a lossy common form

The record format's RFC 8785 subset permits only integer-valued numbers, and
JSON readers that parse numbers into IEEE-754 float64 (every browser, Node, and
most tooling) silently round integers beyond ±(2⁵³−1). So at record-build time
the recorder normalizes numbers to a form every reader recomputes identically:
non-integer floats and integers beyond ±(2⁵³−1) are stored as their exact
decimal strings; integers within that range stay numbers. In the TypeScript
package, BigInt values follow the same rule (kept as numbers while exact in
every reader, exact decimal strings beyond). Note the input-side boundary:
"exact" preservation applies to inputs that carry exact values — Python ints
and JavaScript BigInts. A plain JavaScript `number` beyond ±(2⁵³−1) has
already been rounded by the language before the recorder sees it; the stored
string is exact for the value received. Pass BigInt when full precision
matters.

Two consequences to know before relying on a record's `data`/`outcome` values:

- **The original type is not preserved.** A caller-supplied float `0.5` is
  stored as the string `"0.5"`; an integer `9007199254740993` and the literal
  string `"9007199254740993"` produce byte-identical records and therefore
  identical hashes. Relative to an established chain head (section 9), the
  chain is tamper-evident for the canonical bytes; it does not prove what
  JSON type the caller originally passed.
- **If type fidelity matters for your evidence, encode it explicitly** — for
  example, record `{"score_millis": 500}` instead of `{"score": 0.5}`, or wrap
  values as `{"type": "int", "value": "9007199254740993"}` in your payload.

This trade was chosen so that an untampered chain verifies identically in every
reader, and so that no caller-supplied number can crash the recorder mid-run.
