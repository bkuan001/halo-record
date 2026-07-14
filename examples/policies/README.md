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

Both are starting points, not official certified mappings; rename and tune the
rules to your agent's tools and your buyer's contract.
