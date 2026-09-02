# Privacy

halo-record is local-first by design. This page consolidates, in one place, what the recorder stores, what leaves your machine, and where the limits are. [LIMITS.md](LIMITS.md) is the authority on what halo can and cannot *prove*; this page is the authority on what it *collects*.

## What a record stores

- Each record describes one agent action: the agent and model identifiers you configure, the action type and tool name, authorization fields, the subject (tenant/customer) id you assign, timestamps, and the integrity hashes that chain records together.
- Tool inputs are stored as a canonical hash plus a redacted summary capped at 200 characters — the complete raw value is never written, though a summary can carry fragments of it, because redaction is best-effort (see the next section). Outcome summaries pass through the same redaction.
- Scanner findings carry a type, a severity, and a short redacted excerpt (for example, a card's last four digits or a masked email); the `data.pii_types` field lists the detected *types* only. Passing `summaries=False` drops summaries, finding excerpts, and any custom outcome fields, leaving hash-only records — finding types and severities plus the schema's non-text outcome fields. Fields you supply yourself still seal as given (the authority block, custom `data.*` keys, non-`sample` keys on your own findings) — keep them payload-free if the record must stay hash-only (LIMITS §13).
- Authority snapshots (`HALO_AUTHORITY_FILE`) get known secret formats masked at seal time, but hashes and refs pass through untouched and free-form text is not detected — keep them to hashes and refs, not raw prompts or private policy text (LIMITS §6).

## Redaction is best-effort

Detection is deterministic pattern matching plus a high-entropy catch-all (long random-looking strings) — never a model judgment. Coverage is by named pattern (API keys, cloud and provider tokens, private-key blocks, database connection strings, JWTs, bearer tokens, credit cards, SSNs, IBANs, emails, phone numbers, internal IPs), so it is best-effort, not comprehensive: free-form personal data with no fixed shape — a person's name, a postal address — has no reliable pattern and is not detected. Treat redaction as defense-in-depth for an artifact handed to a third party, not a guarantee that a summary can carry no personal data (see LIMITS §6).

## What leaves your machine

Nothing, except three opt-in calls — all off unless you invoke them:

- **RFC 3161 timestamping** (`halo anchor`) sends only a checkpoint's state hash to the Timestamp Authority you choose.
- **Anchoring to a witness** sends the subject id, a record count, and two chain fingerprints — never record contents.
- **Reading a witness's checkpoints back** (completeness verification) sends the subject id being checked.

The witness is a server you run or designate (`halo witness-serve`) — there is no vendor-hosted endpoint, and no default endpoint is configured. Record contents never leave your infrastructure.

## What halo does not do

- No telemetry, no analytics, no accounts, no sign-in. Installing and running halo tells the maintainers nothing.
- No third-party services are contacted except the three opt-in calls above.

## Demo and sample data

Output from `halo sample` and `halo demo` is fictional — placeholder companies and addresses (Acme Corp, Globex, `alice@acme-corp.com`). No real user data appears in this repository or its demos.

## Retention and deletion

Records are plain JSONL files on infrastructure you control; halo imposes no retention, and protecting the files — encryption at rest, access control — is your infrastructure's job, like any sensitive log. Deleting records is an operator decision, with one interplay worth knowing (LIMITS §1): editing or removing records *inside* an established chain breaks verification visibly, but a self-held chain that is truncated and re-sealed still verifies — detecting deletion outright requires a reference point outside the chain. In plain terms: changing a page of the diary is visible to anyone holding it, but tearing pages off the end and re-doing the fingerprints is not — unless someone outside holds the page count and the last fingerprint. That is what a witness checkpoint provides, for every record it covers; records written after the last checkpoint are not yet covered.

## Reporting

Found a data-handling concern, or a sensitive-data pattern the redactor should know about? [SECURITY.md](SECURITY.md) describes the reporting channel. Any path that lands unredacted input in a record is in scope as a vulnerability.
