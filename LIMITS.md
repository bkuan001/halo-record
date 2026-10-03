# halo-record — Architectural Limits

What halo-record does not do, by design. These are boundaries, documented so a
reviewer can evaluate the system on its own terms. Each one states what holds, what
does not, and what to say when an assessor asks.

---

## 1. A self-held chain proves integrity, not completeness

The hash chain proves no record was edited, reordered, or truncated *relative
to a head you already know*. It cannot prove the operator never wrote a record
in the first place, or did not remove records — from the tail or from anywhere
in the chain — and re-seal the remainder before anyone saw it. A re-sealed
chain verifies clean; only a checkpoint captured before the re-seal exposes it.

**What closes it:** a witness outside the operator's control holding periodic
checkpoints — the subject id, a record count, and two chain fingerprints (the head and the chain root). The witness protocol ships in
this repo (`halo witness-serve`, `halo anchor`); a hosted, recognized witness
is the piece still being built.

Checkpoints are unsigned. A checkpoint file presented to you *by the operator*
proves nothing — it can be rewritten in a few lines to match any re-sealed
chain. The closure only holds when you fetch the checkpoint from the witness
yourself, or hold your own copy captured earlier. Signed witness receipts are
deliberately outside the zero-dependency core; until they exist, treat any
relayed checkpoint as the operator's assertion.

**Pin the subject.** Checkpoints are looked up by the subject id the records
carry, and the vendor writes that id. A chain re-keyed to another subject id is
checked against that id's checkpoints, so it can read as unwitnessed, or as
consistent with checkpoints the vendor anchored under the new id, while the
customer's own checkpoints are never consulted. `halo anchor --check
--expect-subject <id>`, `halo report --expect-subject`, `halo export
--expect-subject` and the report page's subject field look up the id you
expect; a chain carrying any other is refused (`report`, `export`), reported
INCOMPLETE (`anchor --check`; exit 1 in all three) or shown as SUBJECT MISMATCH
(the page). Without one, a completeness
verdict is about the id the vendor chose.

**A damaged witness is refused.** A witness file with a torn or garbled line,
or a line without a checkpoint's shape, is not read around: the damaged
checkpoint may be the one that exposes a truncation. `halo anchor --check`,
`halo report` and `halo export` refuse it with exit 2, the code they use for a
missing witness file, and the hosted witness answers reads with 503 until its
operator restores the store.

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

The same distinction applies to *disclosure*. A timestamp proves the chain
reached a state no later than the attested time — not that anyone outside the
operator had seen it by then. An operator can hold a genuine, anchored
checkpoint private and surface it only when convenient; nothing in the
artifact records when a reader could first have fetched it. What bounds this
is the reader's side of the protocol: fetch checkpoints from the witness on
your own schedule, or demand a fresh anchor at review time — a new timestamp
over the current head proves the chain's state as of your request, so
staleness is bounded by how recently you asked, not by what the operator chose
to surface. (Transparency logs bound the same gap with fixed merge-delay
rules; a hosted witness would bound it by publishing its own received-at time
for each checkpoint — which is then the witness's assertion, not the
operator's.)

**Who can read the witness.** `halo witness-serve` serves
`GET /v1/checkpoints?subject=<id>` without credentials by default, so a
buyer's browser can fetch checkpoints while it re-verifies a Runtime Report,
and a reviewer can check completeness with no account and no key the vendor
hands out (`halo anchor --remote --check` needs no vendor key). The cost is
disclosure: anyone who guesses a subject id learns that it is anchored and its
record count. Setting `HALO_WITNESS_READ_KEYS` (`key=subject-glob|…`, every
read key scoped) makes per-subject reads require a bearer key scoped to that
subject (401 without one, 403 out of scope); reads by `chain_root` — a 64-hex
fingerprint, not a guessable name — stay open. `halo anchor --remote --check
--key <read key>` carries one; `halo report --witness-url`, `halo export
--witness-url`, and a report page's live fetch do not, so with read keys on
they cannot read a subject's checkpoints (report and export then refuse rather
than render or export an unchecked result).

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
The tier is declared by the integration that built the record (its `source`
argument) and sealed as declared — the recorder does not attest to it, the same
standing as the agent and principal blocks (§5, §10). A record with no source
tag carries no tier claim at all.

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

Raw tool arguments are hashed; a summary capped at 200 characters is stored
alongside, and a short input that matches no pattern appears in it in full.
The summary layer is scrubbed by
provider-specific patterns plus an entropy catch-all — defense in depth, not a
proof. A novel secret format can land in a summary. Values under path-typed
argument keys (`file_path`, `path`, `paths`, `pattern`, `url`, and the like)
are left readable when they are anchored as a path (leading slash, drive
letter, scheme, dot-relative prefix, file extension, or glob character) and
carry no `= ? & % @`. "Path-typed" includes URL keys (`url`, `uri`, `href`),
so a capability URL whose secret is a path segment stays readable there
unless a named pattern covers it; Slack, Discord, and Teams webhook URLs are
named patterns. They are still scanned: named patterns mask there as
everywhere, and an entropy hit under a path key is reported as a
`high_entropy_path_value` (LOW) finding instead of being masked, so
`findings: []` still means the scanner found nothing in the fields it scans (the arguments, the outcome, and caller-defined outcome and `data` fields — see §13 for the fields it does not), unless the integration supplied its own `findings`, which are sealed as given and bypass the scan (§13). A path inside
free text — a shell command, a tool response — is subject to the full
catch-all and may be masked as a secret, which also raises that record's
severity to HIGH; the file named in a patch header (`*** Update File:`) is
treated as a path value. The report's headline "Flagged" count is
severity-weighted: LOW notes are counted separately. Masks hide the credential,
not always its context: the connection-string mask removes the password only,
so a DSN's username and internal hostname survive into the summary. If you find a path that
does, that is a vulnerability report we want (see SECURITY.md).

Two bounds keep the scanner linear on hostile text. A stored text value is
masked up to its first 65,536 characters and the rest is withheld, replaced by
`[… N more characters withheld]`. The cut never falls inside a pattern match
or a token: every pattern is matched first over the text up to 4,096
characters past the cap, and the cut moves back to the start of any match it
would split, so a grouped card number, SSN, IBAN or phone number is either kept
whole (and masked) or withheld whole. Within that rule the cut lands after
whitespace, else after a character that cannot be part of a token; a value
with no such break point (one unbroken token) is withheld whole. A single
match longer than 4,096 characters that runs past that window is seen only as
far as the window reaches. Findings still cover the whole text, scanned in
overlapping windows. Invisible characters spliced inside a token are dropped before
matching, so they cannot split a key. The set is every Unicode format character
(category Cf) and every Default_Ignorable_Code_Point, both as of Unicode 15.1
(this covers the soft hyphen, the combining grapheme joiner, Hangul fillers,
the Khmer inherent vowels U+17B4/U+17B5, variation selectors and tag
characters), plus U+2800 BRAILLE PATTERN BLANK and U+1D159 MUSICAL SYMBOL NULL
NOTEHEAD. "Inside a token" means between two of `A-Z a-z 0-9 _ - + / = . :`
(the second may also be `@`). They are also dropped between a whitespace
separator (space, tab, newline, no-break space, U+2007, U+202F, and every other
character Python's `str.isspace()` accepts) and one of those token characters
or a parenthesis, in either order, so `4539\u200b 1488\u200b 0343\u200b 6467` with a
zero-width character beside each space, or a PEM header with one beside a
space, is matched as the grouped number or header it renders as, then masked
whole (a hyphen or dot separator is already a token character). Elsewhere (an
emoji sequence, a bidi mark between two spaces) they are kept. They are
dropped only to find secrets: a value in which nothing is masked (an agent id,
a tool name, a session id, prose) is stored exactly as given, invisible
characters included. Because identifiers keep them, two ids can differ only by
an invisible character (`payments\u200b-bot` and `payments-bot`). The policy engine
compares strings with invisible characters removed, so a rule on `agent.id`,
`action.tool` or `session_id` matches the lookalike too (§7); the report shows
each invisible character in an agent, tool or session id, a scope, an approver
or a principal as a visible marker (`⟨U+200B⟩`), in the table, the Tool filter
and the record drawer; and `halo policy`, `halo report` and `halo export` print
a warning naming each record whose agent, tool, session or subject id, scope,
approver or principal carries one. The export's CSV keeps those cells exactly
as recorded, so it ties out to the records byte for byte; its manifest lists
them under `invisible_identifiers`. Matching `halo export --tool` is exact, so a
lookalike tool is not selected by the visible name. A lookalike built
from visible characters (a Cyrillic `а` for a Latin `a`) is not detected.

The credential coverage, by finding type:

- `db_conn` — connection strings with the schemes `postgres`/`postgresql`,
  `mysql`, `mariadb`, `mongodb`/`mongodb+srv`, `redis`/`rediss`,
  `amqp`/`amqps`, `mssql`, and `sqlserver`; the password is masked.
- `private_key` — PEM and PGP armor blocks of any private-key label (RSA, EC,
  DSA, OPENSSH, `ENCRYPTED PRIVATE KEY`, `PGP PRIVATE KEY BLOCK`), masked
  whole; a block cut off before its footer has its body lines masked too.
- `password` — a password assigned in text: `password=…`, `DB_PASSWORD: …`, a
  JSON `"password": "…"` pair (also `passwd`, `passphrase`, `pwd`).
- `credential_field` — a value under a credential-named key (`password`,
  `passwd`, `passphrase`, `secret`, `token`, `api_key`, `private_key`,
  `secret_key`, `auth`, `authorization`, `credential(s)`, `pass`, `pwd`,
  including suffixed forms like `db_password` or `db_pass`) is masked whole
  as `****` whatever its shape — `{"password": "hunter2"}` is masked though
  `hunter2` matches no pattern. A number under a password-named key is masked
  the same way.

Known gaps in that coverage: a password in free prose with no assignment —
`pw hunter2`, `login with password hunter2` — is not detected. Card numbers
are matched at 13–17 digits on the Visa, Mastercard 51–55, American Express,
and Discover 6011/65 prefixes, undelimited or with digit groups separated by
spaces, hyphens, dots, or no-break spaces (U+00A0, U+2007, U+202F); other ranges (Mastercard 2-series, UnionPay,
JCB, Maestro) are not matched. A 19-digit card number is not detected as a
whole: undelimited it passes through unmasked, and grouped at most a leading
16-digit run is masked, leaving its last digits readable.

**Hash-only mode** (`summaries=False`) also covers identifier fields: in
`session_id`, `parent_id`, `version`, `ref`, `policy_ref`, any `id`, and the
`agent` and `threats` blocks, a token in a known secret format is masked as in
summaries (`ghp_****`, `sk-a****`), and any other secret-shaped token is
replaced by `sha256:` plus 16 hex digits of its digest — deterministic, so
equal ids still group and link — while UUIDs and hex ids are kept as written. A
masked id keeps only a prefix or its last characters, so two secrets of one
format can mask to the same id. `subject.id` is
the exception: it is stored as given, because it routes the record to its
tenant's chain. With summaries on, those identifier fields skip the
high-entropy catch-all (it would mangle legitimate opaque ids) and get named
formats masked only, so a random-looking secret used as an id is stored as
written.

The `authority` block gets a narrower pass than summaries: known secret and
personal-data formats (API keys, tokens, private-key blocks, connection
strings, emails, SSNs) are masked at seal
time, but the high-entropy catch-all is deliberately not applied — legitimate
authority values are hashes and refs, which look exactly like entropy — and
free-form text is not detected. Beyond those named formats, the hashes-and-refs
convention remains unchecked.

The same bound applies to `data.pii_types`: it is derived from the scanner's
*named* personal-data categories (email, ssn, credit_card, phone, iban), so it
is a floor, not a census. Within a category the coverage is by shape: cards and
IBANs are caught in their spaced, hyphenated, dotted, and no-break-space printed forms, including mid-sentence (cards Luhn-checked, IBANs mod-97-checked, so look-alike identifiers are not classified — a two-digit checksum still passes about 1 in 97 random look-alikes);
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

A policy is validated against the record schema before it runs, so a rule
cannot pass by matching nothing: values outside a field's allowed set, values
of the wrong type, `null`, non-finite numbers or numbers beyond 2⁵³−1,
matchers that do not apply to the field, contradictory matchers, and duplicate
JSON keys are refused (exit 2). The two free-text type fields take only a known
vocabulary in a policy: `findings[].type` the scanner's finding types (section
6), `threats[].type` the documented threat types (`policy_violation`,
`prompt_injection_direct`, `prompt_injection_indirect`, `tool_misuse`). A
threat type outside that list, as a detector of your own may emit, cannot be
named in a policy. A rule whose `when` already decides its outcome on a
single-valued field is refused too: a `forbid` that no selected record can meet
(`when action.type=network`, `forbid action.type=read`) or a `require` that
every selected record meets, since either can never be violated. A rule whose
`when` selects no record reports "matched no records", never PASS. Validation
catches a rule that cannot mean what it says; it cannot catch a valid rule
aimed at the wrong field.

String values are compared with invisible characters (the set in §6) removed,
on the record side and in the rule alike, in `halo policy` and in the page's
evaluator. A rule naming `payments-bot` therefore also matches a record whose
agent id is `payments\u200b-bot`; the record itself keeps the id as written, and
`halo policy` prints a warning naming it.

A verdict names its policy by `Policy sha256`: the SHA-256 of the policy file's
bytes, the value `shasum -a 256 <file>` prints. A report page carries the
policy file's text and re-reads it in the browser exactly as `halo policy`
reads the file, refusing the same texts (a repeated key, a non-finite number,
an invalid rule) with the same reason. Those rules were embedded by whoever
generated the page: a matching digest says the page used the file you hold,
not that the file is a sound policy, so run `halo policy` on that file
yourself.

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

A gate's `blocked` does not outrank the recorded outcome. The report reads a
record as stopped ("Blocked by gate", "Denied") only when its outcome is
recorded as `denied`. When a record says `verification.status: blocked` (or
`authorization.decision: denied`) and its outcome is recorded as `ok` or
`error`, or not recorded at all, the report shows both ("Gate reported
blocked; outcome recorded: error", "Decision recorded denied; outcome not
recorded") and prefers neither. The starter packs' egress rules draw the same
line: they take a record out of scope only when its outcome is recorded as
`denied`, so a gate's report alone never removes a record from an egress
check, and the page never calls a record blocked that the egress rule counts.

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
can carry personal data, and only the summaries and caller-defined `outcome` and
`data` fields are scanned at all.

| Field | How it goes wrong |
|---|---|
| `principal.human_id` / `creator_id` / `role_scope` | names the person the action ran on behalf of — teams put a work login here, which is usually an email address |
| `action.authorization.approver` / `scope` / `decision` | the approving person's name or login, and values built from one |
| `outcome.*` (keys other than `summary`) | scanned with the summary patterns and masked (not cut to 200 characters; text past 65,536 characters is withheld) — a detected secret or personal-data pattern produces a finding (and `data.pii_types`) — but a name or postal address has no pattern, so a result field like `customer` or `address` seals a person's details permanently |
| `session_id`, `parent_id` | free-form; often built by joining a user identifier to a date |
| `agent.*`, `source.*`, `authority.*` | free-form labels — a laptop, an assistant, or a runbook named after a customer |
| `action.tool` | a tool name built from the thing it acts on |
| `threats[].type` / `.ref` | ticket references and notes copied from an upstream detector |
| `data.*` | any key you add beyond `region` / `purpose` / `cross_region` — scanned and masked like `outcome.*` (not cut to 200 characters), with the same gap for names and addresses |
| `action.input.summary`, `outcome.summary` | redacted best-effort only — and per section 6 a **name or postal address has no reliable pattern, is not detected, and is not masked** |
| `findings[].type` / `.sample` | masked fragments *when the scanner produced them* — a masked email keeps its full domain and an SSN keeps its last four. Findings you supply yourself keep only `type`, `severity` and `sample`: the `sample` is masked like a summary, and any other key is dropped |

Note what `summaries=False` does and does not empty: human-readable summaries,
`findings[].sample` excerpts (from scanner findings and findings you supply
alike), and custom `outcome` keys are all dropped, but `data.pii_types` (detected
type names) survives, and the `authority` block is stored even then (with known
secret and personal-data formats masked; see section 6). On findings you supply,
keys other than `type`, `severity` and `sample` are dropped.

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
- **An integer of more than 4,300 digits** (Python 3.11+ refuses to print one)
  is stored as the text `[integer of N bits]`, in every Python version.
- **If type fidelity matters for your evidence, encode it explicitly** — for
  example, record `{"score_millis": 500}` instead of `{"score": 0.5}`, or wrap
  values as `{"type": "int", "value": "9007199254740993"}` in your payload.

The argument hash (`action.input.hash`, the `input_hash` export column) is
computed separately from the record hash and over the arguments **as passed**,
before the normalization above: `sha256:` over the RFC 8785 canonical JSON of
the arguments when they canonicalize, otherwise over a sorted-key, no-whitespace
`json.dumps` of them (so a non-integer float hashes as its literal, and a value
JSON cannot represent — a date object, say — hashes as its string form). To
re-derive it from source data, serialize the same arguments the same way;
`halo hash '<json>'` prints the result for any JSON input. Key order does not
matter; whitespace and the float-vs-string distinction do.

This trade was chosen so that an untampered chain verifies identically in every
reader, and so that no caller-supplied number can crash the recorder mid-run.

---

## 15. Timestamps are declared; the sealed order is the chain order

A record's `ts` is the recording host's clock, as the producer declared it.
The order the chain proves is the order records were sealed — each record's
`prev_hash` commits to the one before it — not the order of their timestamps.
`halo verify` compares each parseable `ts` with the previous record's (offsets
applied, to the nanosecond) and, when one is earlier, prints a warning naming
both records' timestamps and a summary count:

```
record 3: warning: ts 2026-06-01T11:00:00Z is earlier than the previous record's ts 2026-06-01T12:00:00Z
warning: 1 record(s) carry a ts earlier than the record before them; ts is declared by the producer, and the sealed order is the chain order (see LIMITS.md).
```

The warning does not fail verification: clock adjustments, retries, and
records built ahead of their append all produce it legitimately. It can also
mean a backdated record, and the chain alone cannot tell the two apart. What
bounds time from outside is an RFC 3161 timestamp on a witness checkpoint
(§1).

**What you say to a reviewer:** "Order is proven by the hash links; time is
the producer's statement. A timestamp that runs backwards is surfaced on every
verification, and the external time proof is the anchored checkpoint."

---

## 16. A torn or truncated tail is kept, reported, and fails verification

A crash mid-write, a full disk, or a truncated copy can leave the last line of
a chain file incomplete. The recorder does not repair or remove it. On the
next append it keeps those bytes in place, prints a stderr warning (`N line(s)
at the end of <file> are not a complete record (a torn write, a truncation,
or a line that repeats a key); they are kept in place, the next record links
to the last complete record, and halo verify will report them`), ends the torn line, and
writes the new record on its own line, linked to the last complete record. A
file with no complete record at all keeps its bytes too, and the chain starts
after them.

`halo verify` reports each line that is not a complete JSON record separately
(`record N: not valid JSON: …`); such a line is not a link in the chain, so the
records around it are checked against each other. The file still fails, with
its own summary — `N line(s) are not complete records (a torn write or a
truncation; see above); the hash chain of the remaining records is intact` —
distinct from a broken link. A torn line is evidence that a write did not
complete; whether a record was lost there is what a witness checkpoint
answers (§1).

`halo verify`, `halo report`, `halo export`, `halo policy`, and the witness's
checkpoint log split a file the same way: on `\n` only, with a carriage return
treated as JSON whitespace and a leading byte-order mark skipped, so each sees
the records `halo verify` checked.

**A repeated key is refused.** A line in which one JSON object repeats a key,
at any depth, fails verification (`record N: duplicate key 'k' in one object
— …`), and `halo report`, `halo export`, `halo policy`, `halo anchor`, `halo
serve` and the witness refuse to read it; the report page's in-browser
verifier fails it too. JSON parsers disagree on which of two repeated values
wins, so such a line could show one reader a value the hash never covered. The
recorder never writes one, and the appender does not take such a line as the
chain's head.

---

## 17. One chain file per subject

`TenantRecorder` writes one file per subject id. Records with no subject go
to the default chain; a record whose subject id is literally the default's
name (`_local` unless configured otherwise) is a real tenant and gets its own chain file, never the
subjectless one.

**Upgrading over files from an earlier version.** An earlier version could
leave several subjects in one file. When a subject's earlier records share a
file with other subjects, they cannot be continued without mixing tenants:
those records stay where they are, the subject's new records start their own
chain in its digested file (`<name>~<digest>.jsonl`), and the recorder says so
on stderr, naming both files. Verify and report the two files separately; the
new chain starts at genesis and does not link to the earlier records.

**Naming a chain to `halo grant`.** A chain is named by its subject id or its
file name. A subject id is chosen by whoever writes the records, so it can
equal another tenant's digested file name; a name that is one chain's subject
id and another chain's file name is refused (exit 2) and both files are
listed. Name the chain by a file name that is unique.

A grant follows the subject id, not the file. A file whose name names one
tenant while its records carry another tenant's subject id (`globex.jsonl`
holding subject id `initech`) cannot take a grant: `halo grant` refuses it
(exit 2), by file name or by subject id, until the file is renamed or moved.
If such a file sits beside another file for the same subject, `halo serve`
withholds that subject (its link opens nothing) and names the files at
startup, rather than guess which file an existing grant was meant for.

**Granting a chain whose report is withheld.** `halo grant` refuses (exit 2)
a name whose report `halo serve` would withhold: a chain that does not
verify, or a file holding records for more than one subject (several subject
ids, or records with and without one). Such a file is keyed by its file name,
so a grant on it could otherwise pass to a later chain whose subject id is
that name. Split or restore the file, then grant each chain.

**Granting a chain with no subject id.** A chain whose records carry no
subject id (a plain `Recorder` file such as `agent.jsonl`) is keyed by its
file name. `halo grant` accepts it, prints a warning on stderr
(`agent.jsonl holds no subject id, so its chain is keyed by its file name`),
and records the grant for that file (`"file": "agent"` in
`.halo_access.json`). The grant admits its recipients only while that file is
the chain served under the name: if a chain with subject id `agent` appears
later, it is served under `agent` instead, the grant admits no one to it, and
`halo serve` prints the grant at startup. A later `halo grant` for the new
chain does not inherit the earlier recipients; they move to `quarantined`.

**Granting a name that matches no chain.** `halo grant` stores a grant for a
name that is neither a served subject id nor a chain's file name, so a
recipient can be designated before a customer's first record. It exits 0 and
prints a warning on stderr: `no chain in <dir> has subject id or file name
'<name>'`, that the grant admits its recipients to the chain for that subject
id if one appears later, and any served subject ids that the file-name
cleaning maps to the same name, ignoring case (`initech.` for `initech`). Check the name against the operator console before sending a link.

**Serving a directory first served by 0.2.45.** 0.2.45 keyed share links and
grants by file name (`Acme_Corp` for subject id `Acme Corp`); 0.2.46 keys
them by subject id and marks each grant it writes as keyed by subject id
(`"by": "subject"` in `.halo_access.json`). At startup, `halo serve` (and
`halo grant`, before it adds a recipient) reads each unmarked grant both ways:

- If `<name>.jsonl` holds exactly one subject id, `<name>`, and that subject
  is served, both readings name one chain: the grant is marked and keeps
  working, silently.
- If `<name>` is a served subject id but `<name>.jsonl` holds a different
  subject id, holds several subject ids (an earlier version could clean two
  ids to one file name, and such a file is keyed by its file name), holds no
  subject id (a plain `Recorder` file such as `agent.jsonl`, also keyed by its
  file name), or no longer exists, the readings can name different chains. The
  grant is quarantined: its recipients move to `quarantined`, it admits no one,
  and every startup until it is re-issued prints `quarantined grant '<name>'
  (recipients: ...)`,
  naming the file and the chain now served under that subject id, with
  `halo grant <dir> <subject id> <recipient>` to re-issue it. It is not
  carried to either chain. For a file that holds no subject id and is still
  the chain served under `<name>`, the line says so and gives
  `halo grant <dir> <name> <recipient>`; a grant re-issued that way is
  recorded for that file (see "Granting a chain with no subject id" above).
- If `<name>` is not a served subject id, and `<name>.jsonl` is served under a
  subject id that file name matches (`Acme_Corp.jsonl` for `Acme Corp`), the
  grant is carried to that subject id and printed as `carried grant`, and the
  earlier share link keeps opening the same report.
- Otherwise the grant is left in place and printed as `grant '<name>' ...
  matches no served chain, so it admits no one now`, with how to re-issue it.
  The line also says it can become active later: if a file `<name>.jsonl`
  appears holding only subject id `<name>`, the grant is marked and admits its
  recipients to that chain; if it appears holding one subject id whose cleaned
  file name is `<name>`, the grant is carried to that subject id as above.

The same rule is applied on every request, so an unmarked grant is never read
with the subject-id meaning before startup has run. A recipient added with
`halo grant` to a name that still holds an unmarked grant does not inherit
it: the earlier recipients move to `quarantined`.

Share links cannot be marked the same way: a 0.2.45 link for `initech.jsonl`
is the same token as the link for subject id `initech`. With gating on, that
token opens only the sign-in page of the chain served as `initech`, and only
that chain's recipients get past it. With gating off (`--open`), the link is
the only check, so a served subject id that is also another chain's file name
opens nothing by its link, and `halo serve --open` prints `link withheld:` for
it at startup. That covers a `<name>.jsonl` holding a different subject id or
several subject ids; a `<name>.jsonl` holding only subject id `<name>` is the
same chain, and its link keeps working.

---

## 18. A record that cannot be written is reported, not raised

Records are written after the action runs; halo-record never blocks an action
on its record, and writing before the action is not offered. When an append
fails (disk full, permissions, a lock held past its timeout, or, for `halo
hook`, a chain directory it cannot create), `trace()`,
`record_call`, `@record`, the OpenAI Agents, LangChain, LiteLLM and OTel
adapters, the MCP wrapper and `halo hook` pass the action's own result or
exception through unchanged and print one line to stderr:

    halo-record: FAILED to record '<tool>' (<ErrorType>: <message>); the action ran, but its record is NOT in the evidence log. The action's own result or error is passed through unchanged (set HALO_STRICT_RECORDING=1 to raise instead).

`@record` and `trace()` wrap an `async def` function in an `async def`
wrapper that awaits it, so the record (or the boundary record) holds what the
coroutine returned or raised, written after it ran; a cancellation is recorded
as an error.

When there is no usable stderr (`pythonw`, a closed file descriptor 2), the
same line is logged on the `halo_record` logger instead, and the action's
result still passes through.

The chain itself cannot show a record that was never written: the remaining
records still verify. A reviewer watching the witness checkpoint cadence sees
a chain that has *stalled* (an expected checkpoint that never arrives, section 1), but no
witness can reveal a single record that was never written while later records
were: the stderr line is the only signal for that.

`strict_recording=True`, or `HALO_STRICT_RECORDING=1` in the environment,
raises the recording error after writing the same line (its tail then says
strict recording is on). The action has already happened by then; a caller
that reads the error as a failed action and retries repeats the action. Where
the error goes depends on the wrapper:

| Wrapper | Strict mode |
|---|---|
| `trace()`, `record_call`, `@record`, MCP wrapper, OpenAI Agents hooks | raised to the caller |
| LangChain `HaloCallbackHandler` | the handler sets LangChain's `raise_error`, so LangChain raises it to the caller of the tool |
| OTel `HaloSpanExporter` | cannot reach the application: the SDK's span processor catches what an exporter raises and logs "Exception while exporting Span". The exporter tries every span in the batch, writes a line per lost span, then raises the first error to the SDK |
| LiteLLM `HaloLiteLLMLogger` | cannot reach the caller: LiteLLM runs callbacks after returning the response and logs what they raise ("LiteLLM.LoggingError: [Non-Blocking] ...") |
| `halo hook` | the hook exits 1 after the stderr line; the agent harness decides what that means |

For the OTel and LiteLLM adapters the stderr line (and the framework's own
log) is the only signal in either mode.

**What you say to a reviewer:** "A failed write is reported on stderr and the
action's outcome is unchanged; only the stderr log reveals a single missing
record (a reviewer watching the witness cadence sees a chain that stopped). Strict mode turns that
into an error, raised to the caller wherever the framework lets it through, at
the cost of a possible repeated action."

---

## 19. A vendor-supplied report page can be restyled to mislead

The HTML Runtime Report is a convenience view, not evidence. A vendor-supplied
report page can be restyled to mislead: page CSS or added markup can hide,
cover or imitate what the page's scripts wrote, and an edited page can also
change the scripts themselves (the page has no Content-Security-Policy). The
JSONL and `halo verify` are the evidence.

What the page does: its scripts verify the embedded records, re-render the
heading, period, counts and table from them, and say so in the badge
("This page's scripts re-rendered the table and summary from the verified
records; the page's styling and any added content are not checked"). They
withhold the verdict when an element id they write to is repeated, or when
computed layout shows one of the regions they write to (the verdict,
completeness, heading, metadata, period, counts, table, table body and row
count) or an ancestor of it is not displayed, invisible, without area, off the
page, clipped to nothing (`overflow`, `clip-path`), masked, filtered,
collapsed by a transform such as `scale(0)`, or skipped by
`content-visibility`. They check at load, after verification, when late
stylesheets load, on animation and transition events, on resize, when the
page becomes visible, before printing, and at a random time about once a
second. Once the check finds a repeated id, or a hidden region in a viewport
large enough to show it, the page withholds for the rest of its life:
showing the region again does not bring the verified view back. While the document is hidden, or the
viewport is under 100 px wide or tall (a collapsed frame or preview pane),
the hidden-region check waits instead of refusing (a repeated id is still refused at any size): the page keeps the verdict it
last showed, a page first opened that small shows the verified badge until
the viewport grows and the check runs, and a region that is hidden only
while the viewport is that small is not refused.

What it does not catch, among others: text made unreadable while its box
stays (`font-size:0`, transparent color), a region placed under the page
background (`z-index`), an element laid over a region, text added with
`::before`/`::after`, fabricated content placed beside the verified table,
content inside, or slotted through, a shadow root, print-only CSS
(`@media print`), a region hidden only for brief moments (each check looks
at one moment, so an animation that hides a region for a small share of each
cycle, and shows it at the cycle boundary where animation events fire, can go
uncaught for a long time), and any edit to the scripts. A green badge on a
page you did not generate yourself therefore says only that its scripts verified the
records they carry.

**What you say to a reviewer:** "The report page is a view the vendor hands
you, and a page can be restyled. Run `halo verify` on the JSONL (and
`halo anchor --check` against a witness you trust) for evidence; read the page
for convenience."
