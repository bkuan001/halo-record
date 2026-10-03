# Policy packs

A policy is a list of rules that a Halo chain is checked against. Each rule
selects records (`when`), then flags any that match `forbid` or fail to match
`require`, and can mark a control as missing entirely (`expect_evidence`).

Run a verdict:

```
halo policy chain.jsonl aiuc-1-starter.json          # text verdict, non-zero exit on violation
halo policy chain.jsonl aiuc-1-starter.json --html verdict.html
halo report chain.jsonl --policy aiuc-1-starter.json # embed the verdict in the Runtime Report
```

The verdict is computed from the rules alone, never from a model, so it is safe
to carry the report's headline claim. The check is evaluative: it judges records
after the fact as evidence. It does not block anything at runtime.

## Authoring

Rules read dotted record fields; append `[]` to fan out across an array
(`findings[].severity`, `threats[].type`). Matchers: `eq`, `ne`, `in`, `nin`,
`contains`, `exists`, `gt`/`gte`/`lt`/`lte`. A bare value means equality.

```json
{
  "id": "refunds-need-human",
  "source": "vendor policy",
  "severity": "HIGH",
  "description": "Any refund must be human-approved.",
  "when":   {"action.tool": "issue_refund"},
  "forbid": {"action.authorization.decision": {"ne": "human_approved"}}
}
```

## Shipped packs

- **`aiuc-1-starter.json`** — approximates AIUC-1 control areas (data protection,
  human oversight, safety, accountability).
- **`owasp-starter.json`** — approximates control areas from the OWASP Top 10 for
  Agentic Applications 2026 (ASI01–ASI10), the OWASP Top 10 for LLM Applications
  (2025), and the Agentic Security Initiative's Threats & Mitigations research
  that fed the 2026 list. Traceability is the cross-cutting mitigation — the
  tamper-evident record is the forensic basis the ASI list assumes. ASI08 and
  ASI09 are runtime/organizational risks a record policy cannot assert, so the
  pack deliberately leaves them out.

Both packs also ship inside the installed package, so they run by name with
no checkout: `halo policy chain.jsonl owasp-starter` (or `aiuc-1-starter`).
`halo policy --help` prints the rule format.

A policy is validated before it runs: an unknown key, an unknown matcher, a
field path that is not a Runtime Record field, or a rule with no `forbid`,
`require`, or `expect_evidence` is refused (exit 2) rather than reported as a
pass. So is a value a record cannot hold: one outside a field's allowed set
(`"deny"` for `action.authorization.decision`), of the wrong type, `null` (use
`{"exists": false}`), non-finite or beyond 2^53−1; a matcher that does not apply
to the field (`contains` on a string, equality on a list — use `contains` or
`field[]` — or `gt` on a string); matchers that contradict each other; and a
JSON key repeated in one object. `findings[].type` takes only the scanner's
finding types and `threats[].type` only the documented threat types
(`policy_violation`, `prompt_injection_direct`, `prompt_injection_indirect`,
`tool_misuse`). A rule whose `when` already decides it on a single-valued field
(`when action.type=network` with `forbid action.type=read`, or a `require` every
selected record meets) can never be violated and is refused. A rule whose
`when` selects no record reports "matched no records".

Each verdict names `Policy sha256 …`, the SHA-256 of the policy file
(`shasum -a 256 policy.json` prints the same value).

Both are starting points, not official certified mappings; rename and tune the
rules to your agent's tools and your buyer's contract.
