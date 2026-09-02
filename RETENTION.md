# Retention

Guidance for operating halo-record chains under a retention policy — the shape of AIUC-1 E015.3's ask (retention policies, access controls, sanitation practices), stated the way this project states everything: what exists, what doesn't, and what to do about the gap. No compliance claim is made here; your framework mapping is your auditor's call. Scope note: this page covers the chain files themselves — derived copies (CSV exports, manifests, shared report HTML) are separate artifacts your retention policy must reach on its own.

## What exists today

- **Storage you control.** Records are plain JSONL files on your infrastructure. halo imposes no retention and ships no expiry — the only TTLs in the codebase are report-viewer session/OTP timeouts.
- **Access controls for viewers.** The served Runtime Report gates viewers (per-subject grants, email verification); see the README's serve/grant section.
- **Sanitation at write time.** Inputs are hashed with a redacted, capped summary; sanitation is best-effort and its boundaries are documented — [PRIVACY.md](PRIVACY.md) is the authority on what records contain.

## What does not exist today

- **No `halo prune`, no retention enforcement.** Deleting old records is an operator action on files, and it interacts with tamper-evidence: removal inside an established chain breaks verification visibly (that is the product working) — though a chain truncated and re-sealed before anyone outside holds its head still verifies (LIMITS §1) — so naive log rotation will destroy your own evidence value. Plan retention *with* the chain, not against it.

## The pattern that works: prune at checkpoint boundaries

If you anchor checkpoints (`halo anchor`, ideally with an RFC 3161 timestamp), a retention policy can drop an old segment **at a checkpoint boundary** and keep the checkpoint plus its token. What you retain is timestamped, third-party-attested proof that a chain with that head existed at that moment; what you give up is re-verification of the pruned records themselves. That is the trade, stated plainly — and it is a *pattern*, not shipped tooling: today you would implement the file surgery yourself, and records after the retained checkpoint continue to verify from its head only if your segmentation preserves the chain linkage (segment per retention window is the simple way: one chain per period, each anchored, old periods deleted whole).

Two practical rules fall out:

1. **Anchor on a cadence that matches your retention window.** A checkpoint per day/week/month is what makes boundary-pruning possible later.
2. **Rotate chains per period rather than truncating one long chain.** Whole-file deletion of an anchored, timestamped period leaves no half-verifiable stub.

## Personal data and erasure

Anything sealed into a record stays sealed — so field discipline at write time *is* the retention policy for personal data. Arguments are hashed and summarized, but operator-supplied fields seal verbatim — `subject`, `principal`, `approver`, `agent`, `session_id`, `authority`, `data`, and non-`summary` `outcome` keys among them; LIMITS §13's table is the fuller inventory and is a starting point, not a closed list. Use pseudonymous identifiers in those fields and keep the mapping outside the chain in a deletable store; erasure then destroys the mapping while the chain and its verification stay intact. The deletion-vs-tamper-evidence interplay is stated plainly in [PRIVACY.md](PRIVACY.md) and [LIMITS.md](LIMITS.md) §1.

## Mapping vocabulary

For reviewers working a control checklist: retention policies = yours, at the file/segment layer (halo gives you the checkpoint primitive, not the policy); access controls = report-viewer gating plus your filesystem controls; sanitation practices = write-time redaction within the documented limits. The known gap — no enforcement tooling — is stated here and in [AIUC.md](AIUC.md)'s Known Gaps, because a gap named is a gap an auditor can work with.
