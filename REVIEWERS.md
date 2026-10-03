# For reviewers

You've been handed halo-record output as evidence — in a security review, an audit, or a vendor assessment — or you're reviewing this repository itself. This page is the short path to checking everything independently. You should not have to trust the vendor who produced the records, and you should not have to trust this project either.

## Verify a chain in four commands

```
pip install halo-record                      # zero dependencies; the whole install
halo verify audit.jsonl                      # integrity: nothing edited (exit 0 = pass, 1 = fail)
halo anchor audit.jsonl --remote https://<witness> --check --expect-subject <customer-id>
                                             # completeness, fetched from the witness yourself, under the
                                             # customer id YOU expect (0 = complete; 1 = incomplete, or the
                                             # check could not run: an unreachable witness, a refused read
                                             # key, an unreadable chain; 2 = a local witness file that does
                                             # not exist or is damaged — the same code from report and
                                             # export; 3 = unwitnessed)
halo report audit.jsonl -o report.html --expect-subject <customer-id> --witness-url https://<witness>
                                             # your own render of the report from the JSONL
```

With a local witness file instead of a hosted one: `halo anchor audit.jsonl witness.jsonl --check --expect-subject <customer-id>`. Always pass `--expect-subject`: the subject id inside the records is written by the vendor, so a re-keyed chain would otherwise pick its own witness lookup.

Integrity needs no account and no network. `--check` against a hosted witness needs no vendor key; a witness that scopes its reads asks for a read key (`--key`). Verification is recomputation, not attestation: if you'd rather not run this code at all, recompute the SHA-256 chain with any implementation on earth. The chain format is documented in the schema (`halo-record.schema.json`).

For a checkpoint's RFC 3161 timestamp, validate the TSA signature with a standard tool — the exact `openssl ts -verify` recipe is in the [README](README.md) (this library deliberately checks only that the token binds the chain state; the signature check is yours, through a tool that owes us nothing).

## What each verdict does and does not mean

- **`halo verify` PASS** — no record in the file was edited, relative to the verified head. It does **not** say nothing is missing: a self-held chain that was truncated and re-sealed also passes. That boundary is [LIMITS.md §1](LIMITS.md), and the verifier prints it on every clean run on purpose.
- **`--check` COMPLETE** — every checkpoint the witness holds still matches the presented chain. The strength of this verdict is exactly the independence of the witness: a checkpoint *handed to you by the operator* proves nothing — fetch it from the witness yourself, and ask who operates the witness.
- **UNWITNESSED** — the chain was never anchored; completeness is simply unknown, not failed.
- **Damaged witness** — a witness file with a torn or garbled checkpoint is refused (exit 2), never read around: the damaged checkpoint may be the one that would expose a truncation. A hosted witness with a damaged store answers 503, and the check fails (exit 1).
- A chain with no `subject` carries a stated caveat in the verdict: its witness key (`chain_root`) changes if the first record is dropped.

## Policy verdicts

A policy verdict names its rules by `Policy sha256 …`: the SHA-256 of the policy file it was computed from. Reproduce it from the file you hold with `shasum -a 256 policy.json` (or `sha256sum policy.json`; on Windows, `Get-FileHash policy.json`). For a bundled pack run by name, hash `halo_record/policies/<name>.json` in the installed package. On a report page, the rules are the policy text embedded in the page by whoever generated it; the page hashes that text, so a digest that differs from your file's means the verdict was computed under different rules. A matching digest is not enough on its own: it says the page used the file you hold, not that the file is a sound policy or that the verdict is the CLI's. Run `halo policy audit.jsonl policy.json` on the file you hold; it refuses a policy that cannot mean what it says (exit 2), and that verdict, computed by you, is the one to rely on.

## What not to accept

- A verify run performed by the producer, on the producer's machine, with results relayed to you. Run it yourself; that's the point.
- Checkpoints presented by the operator rather than fetched from the witness.
- A report page the vendor rendered, as your verification. It runs code supplied with the report; edit that code and it can say anything. Verify the JSONL yourself with `halo verify` (and `halo anchor … --check`), and render your own report from it if you want the page.
- Any claim beyond the claims table at the top of the README. If the words say more than the table, the table wins — and [LIMITS.md](LIMITS.md) wins over both.

## Citing halo-record evidence

One line, so findings are reproducible:

```
halo-record produced v?.?.? / verified with vX.Y.Z · <chain file> (N records, head <first-8-of-hash>) · verified <ISO date> by <you> · integrity PASS · completeness <COMPLETE n=<checkpoints matched> | UNWITNESSED> via <witness operator or "operator-run">
```

`n` counts the witness checkpoints that matched the presented chain. Cite both versions where they differ — the producing version governs what was recorded, the verifying version governs how it was checked. Keep the full head hash in the workpaper body; the first eight characters are a citation convenience, not the retained value. Where a checkpoint carries an RFC 3161 timestamp, append the `openssl ts -verify` outcome to the line.

Example:

```
halo-record produced v0.2.40 / verified with v0.2.42 · acme.jsonl (1,284 records, head 3f9c2a1d) · verified 2026-09-02 by J. Reviewer · integrity PASS · completeness COMPLETE n=3 via witness.example.com · TSA Verification: OK
```

The version matters (behavior is versioned), the head matters (it pins which chain you saw), and the witness operator matters (it's the independence of the completeness verdict).

## The rest of the paperwork

- [LIMITS.md](LIMITS.md) — what the chain does and does not prove. Read first.
- [PRIVACY.md](PRIVACY.md) — what records store and what leaves the operator's machine.
- [SECURITY.md](SECURITY.md) — reporting channel. Any path that lands unredacted input in a record is in scope.
- Framework mappings: [AIUC.md](AIUC.md) · [OWASP.md](OWASP.md) · [AARM.md](AARM.md) · [ATC.md](ATC.md).
