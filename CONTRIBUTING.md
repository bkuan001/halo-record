# Contributing

Contributions are welcome — issues, discussions, and pull requests alike.

## Ground rules

- **Tests required.** Feature PRs ship with tests; bug-fix PRs ship with a test that fails before the fix.
- **Small PRs merge faster.** One change per PR. If it grows past a few hundred lines, consider splitting it.
- **Schema changes need discussion first.** The record format is a compatibility surface shared with other implementations (including the TypeScript package). Open an issue before changing `halo-record.schema.json`; additive and optional is the bar.
- **AI-assisted contributions are welcome** — most modern code is. You should understand the change and be able to discuss it in review; "the model wrote it" is not an answer to a review question.
- **Zero runtime dependencies is a feature.** PRs that add runtime dependencies will be declined; standard library only.
- **Security issues are not PRs.** See [SECURITY.md](SECURITY.md) — please don't file exploitable findings publicly.

## Process

Every PR gets a full read and a CI run. Expect review comments — they're engagement, not rejection. Response time is usually within a day or two.
