# halo-record × OWASP GenAI Security Project

The [OWASP GenAI Security Project](https://genai.owasp.org) publishes the **Top 10 for Agentic Applications (2026)**, the **Agentic Security Initiative (ASI) Threats & Mitigations** research that fed it, and the **AI Security Solutions Landscape for Agentic AI** — which maps tools across the agent lifecycle (*Scope & Plan · Augment · Develop · Test · Release · Deploy · **Operate · Monitor · Govern***).

halo-record sits in the **Operate → Monitor → Govern** stages. It is **record-only by design** — it does not intercept, guard, or enforce — so it is not a control that *prevents* any of these threats. It is the **evidence layer underneath them**: a tamper-evident record of what the agent actually did, which is the forensic basis the ASI threat list assumes but does not itself provide. Traceability is the cross-cutting mitigation; halo-record is where it comes from.

> **Two distinct things a record does per threat.** Every threat below leaves a forensic trace in the record (that is universal — a record *proves what happened*). Separately, some threats admit a **deterministic policy check** over that record (a rule that flags when the evidence is missing or the wrong shape). The record is always present; the rule exists only where a deterministic check is warranted — a record proves what an agent *did*, never what a control *prevented*.

## Top 10 for Agentic Applications (2026) → halo-record

Coverage marks: **✅ shipped policy rule** · **🟡 template rule** (rename to your own tool/field names before use) · **❌ out of scope** (a record cannot assert this).

| # | OWASP Agentic threat | halo-record rule(s) | Mark |
|---|---|---|---|
| ASI01 | Agent Goal Hijack (+ LLM01 Prompt Injection) | `prompt-injection-mitigated` — no injection may appear unmitigated in the record | ✅ |
| ASI02 | Tool Misuse & Exploitation (+ Agentic T2, T15 HITL bypass) | `tool-misuse-critical-reviewed` (CRITICAL actions out of policy until reviewed); `money-movement-human-approved` (template) | ✅ |
| ASI03 | Identity & Privilege Abuse (+ LLM06 Excessive Agency, Agentic T3) | `excessive-agency-authorized` (consequential actions carry explicit authorization); `privileged-writes-human-approved` | ✅ |
| ASI04 | Agentic Supply Chain Vulnerabilities | `agent-version-pinned` — every record carries the version of the agent that acted, so "which build did this?" is answerable by column | ✅ |
| ASI05 | Unexpected Code Execution | `code-exec-human-approved` (template — name your real execution tools) | 🟡 |
| ASI06 | Memory & Context Poisoning (+ LLM04 Data Poisoning) | `source-integrity-checked` (template — name your provenance/integrity step) | 🟡 |
| ASI07 | Insecure Inter-Agent Communication | `agent-attributed` — every action bound to a specific agent id; the basis for reconstructing cross-agent activity (attribution, not channel security) | ✅ |
| ASI08 | Cascading Failures | **out of scope** — a systemic-runtime property; the record supplies traces for post-hoc reconstruction but asserts no verdict | ❌ |
| ASI09 | Human-Agent Trust Exploitation | **out of scope** — a human/organizational risk outside what a record policy can assert | ❌ |
| ASI10 | Rogue Agents | `purpose-declared` (deviation is detectable only if purpose is declared) + `agent-attributed` | ✅ |

**Cross-cutting (traceability floor the rest of the list assumes):** `actions-traceable` (ASI cross-cutting / Agentic T8 Repudiation & Untraceability — every action timestamped, attributable, non-repudiable); `no-secret-disclosure` and `pii-egress-controlled` (LLM02 Sensitive Information Disclosure; the former also supports ASI03 credential hygiene).

The rules above ship as [`examples/policies/owasp-starter.json`](examples/policies/owasp-starter.json) — run `halo policy <chain.jsonl> owasp-starter.json`. This is an **approximate, community-oriented mapping, not an official OWASP artifact**; corrections welcome.

## Boundaries

- **Tamper-*evident*, not immutable.** Records can be edited; the edit is *detectable* against the hash chain, not *prevented*. The claim is "modification, deletion, or reordering is detectable," never "cannot be changed."
- **Record proves what happened, not what a control prevented.** The two ❌ categories (ASI08, ASI09) are systemic-runtime and human/organizational risks a record policy cannot assert — the record still supplies the forensic trace for post-hoc reconstruction, it just yields no deterministic pass/fail verdict.
- **Integrity is not completeness.** A record the operator holds proves nothing was *edited*, never that nothing was *omitted*. Completeness comes from an independent witness holding a periodic count and head-hash of the chain — see [Integrity vs. completeness](README.md#integrity-vs-completeness-read-this-part). This is the layer that makes the evidence trustworthy to a party outside the operator.

halo-record is the traceability evidence the OWASP agentic threat list assumes — produced tamper-evident, chained, and verifiable by someone outside the vendor.
