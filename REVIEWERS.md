# For reviewers

You've been handed halo-record output as evidence — in a security review, an audit, or a vendor assessment — or you're reviewing this repository itself. This page is the short path to checking everything independently. You should not have to trust the vendor who produced the records, and you should not have to trust this project either.

## Verify a chain in four commands

```
pip install halo-record                      # zero dependencies; the whole install
halo verify audit.jsonl                      # integrity: nothing edited (exit 0 = pass, 1 = fail)
halo anchor audit.jsonl witness.jsonl --check  # completeness against a witness (exit 0 = complete, 1 = incomplete, 3 = unwitnessed)
halo report audit.jsonl -o report.html       # the report re-verifies itself in your browser
```

No account, no key, no network access required for integrity — and verification is recomputation, not attestation: if you'd rather not run this code at all, recompute the SHA-256 chain with any implementation on earth. The chain format is documented in the schema (`halo-record.schema.json`).

For a checkpoint's RFC 3161 timestamp, validate the TSA signature with a standard tool — the exact `openssl ts -verify` recipe is in the [README](README.md) (this library deliberately checks only that the token binds the chain state; the signature check is yours, through a tool that owes us nothing).

## What each verdict does and does not mean

- **`halo verify` PASS** — no record in the file was edited, relative to the verified head. It does **not** say nothing is missing: a self-held chain that was truncated and re-sealed also passes. That boundary is [LIMITS.md §1](LIMITS.md), and the verifier prints it on every clean run on purpose.
- **`--check` COMPLETE** — every checkpoint the witness holds still matches the presented chain. The strength of this verdict is exactly the independence of the witness: a checkpoint *handed to you by the operator* proves nothing — fetch it from the witness yourself, and ask who operates the witness.
- **UNWITNESSED** — the chain was never anchored; completeness is simply unknown, not failed.
- A chain with no `subject` carries a stated caveat in the verdict: its witness key (`chain_root`) changes if the first record is dropped.

## What not to accept

- A verify run performed by the producer, on the producer's machine, with results relayed to you. Run it yourself; that's the point.
- Checkpoints presented by the operator rather than fetched from the witness.
- "The report says verified" without opening the report — it re-verifies in-browser; let it.
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
