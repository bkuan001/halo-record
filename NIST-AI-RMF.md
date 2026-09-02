# halo-record and the NIST AI Risk Management Framework

Where halo-record's output sits against the NIST AI RMF — stated conservatively: the RMF is a voluntary framework organized around four functions (GOVERN, MAP, MEASURE, MANAGE), not a control checklist, so what a record format contributes is *evidence for the activities the functions describe*, not satisfaction of anything.

**Not affiliated with NIST. Not a conformity claim** — the RMF has no certification to claim against. *Last reviewed 2026-09-02, against AI RMF 1.0's four functions.*

## Why the RMF shows up in reviews at all

Two practical routes, both live:

1. **Contracts and questionnaires** cite it as the shared vocabulary for "show me your AI risk program."
2. **Statute**: Texas's TRAIGA (in force since January 1, 2026) gives organisations following the NIST AI RMF a statutory defense — commonly described as a safe harbor; confirm the precise mechanism with counsel before relying on the label — which quietly converts a voluntary framework into a legal posture, and a legal posture into an evidence question: defenses need documentation sufficiently detailed to support them.

## What halo-record produces against the functions

- **MEASURE** — the natural home. Measurement of a deployed agent's behavior presupposes a record of that behavior: per-action Runtime Records are the raw, integrity-protected substrate for monitoring what the system actually did, when, under whose authorization, with what outcome. (AIUC-1's published crosswalk for its logging control cites MEASURE 2.4 and 2.8 alongside the other regimes — see [AIUC.md](AIUC.md).)
- **MANAGE** — responding to incidents and tracking treatments requires reconstructing events; a hash-chained record makes the reconstruction artifact one whose integrity the response team, and anyone reviewing the response, can verify independently.
- **GOVERN / MAP** — indirectly: records carry declared agent identity, delegation links, authorization fields, and (optionally) authority snapshots of the rules context in effect — inventory-shaped facts a governance program consumes, with their trust posture stated in LIMITS §5 and §10 (declared, not attested).

## Known gaps, stated plainly

- The RMF's subcategories describe organizational *activities* — none is "installable." halo-record contributes the record artifact those activities reference; the program, roles, and risk determinations are yours.
- No subcategory-by-subcategory mapping is published here, deliberately: the defensible unit of mapping for a record format is the function level, and stretching further would be vocabulary theater.
