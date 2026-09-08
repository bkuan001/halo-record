# halo-record × MITRE ATLAS

[MITRE ATLAS](https://atlas.mitre.org)™ (Adversarial Threat Landscape for AI Systems) is a public knowledge base of adversary tactics and techniques against AI systems — the AI sibling of ATT&CK. It is a *threat taxonomy*, not a control standard: nothing is certified against ATLAS. Its current releases cover agentic systems directly, with techniques for agent tool invocation on untrusted data, agent context poisoning, exfiltration via agent tool invocation, and credential theft from agent configurations.

halo-record's place in that landscape is one specific mitigation, plus the forensic layer the rest of the matrix assumes.

## The anchor: AML.M0024 — AI Telemetry Logging

ATLAS's logging mitigation describes the record class this project produces — quoted here, with the gaps tabled below:

> "When deploying AI agents, implement logging of the intermediate steps of agentic actions and decisions, data access and tool use, installation commands, and identity of the agent."

Field by field:

| AML.M0024 asks for | What the record provides |
|---|---|
| Intermediate steps of agentic actions and decisions | One sealed record per action, hash-chained in order within a session; `parent_id` links records into delegation/execution trees. Stated gap, same as everywhere else in these docs: reasoning traces are not captured. |
| Data access and tool use | `read` / `write` / `network` / `tool_call` action types with input summary + hash, `outcome`, and MCP context (`mcp.host/client/server`, `action.tool`). |
| Installation commands | Recordable as actions where they flow through an instrumented path — bounded by the capture surface ([LIMITS.md §4](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). |
| Identity of the agent | `agent.id` / `agent.version` / `agent.model` on every record, plus `principal` for who the agent acted for — declared identity, sealed into the hash, not cryptographically attested ([LIMITS.md §5](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)). |

What ATLAS does not ask of the logs — and what this format adds — is trustworthiness to someone outside the operator: AML.M0024 asks for telemetry and is silent on log integrity. A halo-record chain is that telemetry made tamper-evident and verifiable by anyone, with open code and no account or key.

## The forensic layer under the technique matrix

ATLAS techniques describe what an adversary does; detection and incident response then need a trustworthy account of what the *system* did. When an agentic incident is worked — a poisoned context that steered tool use, data exfiltrated through a tool invocation, an agent acting on credentials it should not have had — the questions are which agent, which tools, what inputs, what outputs, in what order, on whose behalf. Those are the record's columns. The chain adds the property incident evidence normally lacks: any edit to the account after the fact is detectable against a verified head. The scope of that property is [LIMITS.md §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md), repeated here because forensics is where it bites: the chain is tamper-evident against everyone *except the party operating the recorder* — an operator (or an attacker who owns the operator's environment) can rewrite and re-seal the whole chain, and only a checkpoint captured outside the operator before the re-seal exposes that. For incident evidence a counterparty can rely on, the chain head must already be held externally — by the relying party or a witness.

Two scope notes, stated plainly:

- **A record is not detection.** ATLAS mitigations include guardrails, permission controls, and monitoring; halo-record intercepts and prevents nothing. It is the evidence those controls and investigations run over.
- **Capture is bounded by instrumentation.** An adversary operating entirely outside the instrumented paths leaves no records — absence of evidence in a chain is a capture-boundary statement, not an all-clear ([LIMITS.md §4](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)).

## One record, several frameworks

AIUC-1's published crosswalk for its logging control (E015) cites **MITRE ATLAS AML.M0024** as the corresponding entry — the same evidence surface mapped in [AIUC.md](https://github.com/bkuan001/halo-record/blob/main/AIUC.md). OWASP's Agentic Top 10 reaches the same layer from the threat side ([OWASP.md](https://github.com/bkuan001/halo-record/blob/main/OWASP.md)). One record, one chain, several vocabularies.

This is a community mapping referencing MITRE's published ATLAS data (v5.x / 2026 releases), not a MITRE artifact; ATLAS is a trademark of The MITRE Corporation. Corrections welcome.
