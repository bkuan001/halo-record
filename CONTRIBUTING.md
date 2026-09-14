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

## Licensing and sign-off

This project is licensed under [Apache-2.0](LICENSE). By contributing you agree that your contribution is licensed under the same terms (Apache-2.0 §5: contributions are licensed inbound exactly as the project is licensed outbound). You keep the copyright in what you write.

Every commit must carry a Developer Certificate of Origin sign-off — the one-line statement that you have the right to submit the code under this license. The text you are certifying is the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Add it with:

```
git commit -s
```

which appends `Signed-off-by: Your Name <you@example.com>` using your git identity. A CI check declines pull requests whose commits lack the line; `git commit --amend -s` or `git rebase --signoff` adds it after the fact.

Trademarks are not covered by the license (Apache-2.0 §6): the name "Halo" and the project's marks stay with the project.
