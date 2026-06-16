# Contributing to BASIS Spec

Thank you for considering a contribution. This repository holds the BASIS standard — its canonical TypeScript representation (`@vorionsys/basis-spec`), the RFCs, and the JSON schemas. BASIS is intended to be an open standard: scrutiny, counter-proposals, and independent implementations are welcome.

This is a small-team project. Open an issue before doing significant work — it avoids effort on a direction that will not merge.

## What we accept

**Spec / constant changes.** Anything that changes a tier boundary, risk level, formula, or other canonical constant is a breaking decision for every downstream implementation. File an issue first with rationale, a breakage assessment, and a proposed version bump (patch / minor / major). Constant changes generally require a minor or major bump and a CHANGELOG entry.

**RFCs.** New protocol surface (manifest fields, proof-event shape, attestation format) goes through the RFC process in `rfcs/`. Copy the style of an existing RFC, open it as a PR marked Draft, and expect discussion before it moves toward Accepted.

**Bug fixes.** Corrections to types, Zod validators, or the proof-chain shape are welcome directly as PRs with a regression test.

**Documentation, typos, clarifications.** Always welcome.

**New independent implementations.** Not accepted in this repository. Build them in your own repo, reference this spec, and we will link back from the README once conformance is demonstrated.

## What we do not accept without discussion

- Changes that **weaken** a constraint (lower a risk level, widen a tier, relax a formula bound) without a documented rationale and an appropriate version bump. Strengthening is easier than weakening.
- Breaking changes to `@vorionsys/basis-spec` exported types without a corresponding RFC or CHANGELOG-documented major bump.
- New runtime/storage/transport opinions. The spec deliberately fixes parameters and lifecycle semantics only; it does not dictate how an implementation stores or transports anything.

## Before you open a PR

- Read the relevant package README and any adjacent RFC.
- Open an issue to discuss anything beyond a typo or a one-line fix.
- Install from the repo root: `npm install`.
- Run the gates that CI runs:
  - `npm run typecheck` (`tsc --noEmit`)
  - `npm run build` (`tsc`)
  - `npm run test` (where present)
- Add or update tests / vectors that demonstrate the change.

## Commit style

Conventional commits are encouraged but not mandatory:

- `feat(spec):` new or changed constant / type
- `fix:` correct a bug
- `docs(rfc):` RFC text
- `chore:` / `test:` housekeeping and tests

## Reporting security issues

Do not open a public issue for security vulnerabilities. See [SECURITY.md](./SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By participating you agree to uphold it.

## License

By submitting a Contribution, you agree to license your work under the Apache License, Version 2.0 (the license this project carries). You retain copyright on your Contribution; the license grants us and all users the right to use, modify, and redistribute under the same terms.

## Who decides what merges

Vorion LLC maintains this repository and has final commit authority. Substantive disagreements about the standard's direction are resolved in the issue tracker / RFC threads with visible rationale. We do not run a formal voting model; maintainers decide with consideration for community input.
