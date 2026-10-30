# BASIS Spec

[![CI](https://github.com/vorionsys/basis-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/vorionsys/basis-spec/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@vorionsys/basis-spec.svg)](https://www.npmjs.com/package/@vorionsys/basis-spec)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Baseline Authority for Safe & Interoperable Systems** — a draft proposal for a shared definition of AI agent trust and governance.

**Status:** Draft. RFC-0001 through RFC-0007 are all marked Draft; none is Accepted or stable. `@vorionsys/basis-spec` is package **1.3.0** (npm dist-tag `latest`). The source exports `BASIS_SPEC_VERSION` **`1.0.0`**, and the conformance tests only check that the string is semver. This repo does not record a 0.9 standard revision or a 2027 ratification date.

**Status:** This repo contains the parameter module and proof-event types (`packages/basis`), RFC-0002 self-tests plus a chain verifier (`packages/basis-conformance`), and reference libraries for draft RFC-0005, RFC-0006, and RFC-0007 (`basis-quorum`, `basis-plan`, `basis-merkle` — in source, not on npm), plus `basis-scorer` and `basis-registry`. RFC-0001 is a draft, a JSON Schema, and an example manifest, with no enforcer here. Live vendor-endpoint conformance is not implemented. BASIS Gate, gate-core, the MCP server, the SDK, and vorion-find are other repositories.

**Status:** Conformance tests exist in `@vorionsys/basis-spec-conformance` (161 tests, 11 files at package 0.5.0) and run under `npm test` after `npm run build`. `.github/workflows/ci.yml` does that on every push and pull request to `main`. `@vorionsys/basis-spec` has no test script. `validate` checks required fields and basic shape only. `verify` recomputes canonical-JSON hashes, walks `previousHash`, and checks detached Ed25519 signatures. A pass is an integrity result on this suite or on a chain record. It is not a trust, compliance, or certification verdict. The badges above are the CI workflow, the live npm version of `@vorionsys/basis-spec`, and the Apache-2.0 file in this repo.

> **Three different version numbers.** RFC status (Draft), `BASIS_SPEC_VERSION` (`1.0.0`), and npm package versions (for example `@vorionsys/basis-spec@1.3.0`) are not interchangeable. `@vorionsys/basis` on npm is a different package (latest 2.0.0, repository `vorionsys/vorion`). This repository publishes `@vorionsys/basis-spec`.

> **This repo and the gate repositories.** The trust parameters, formulas, types, and proof-chain RFCs are here. [`basis-gate`](https://github.com/vorionsys/basis-gate) is a separate repository whose README describes a companion specification for pipeline composition (layer interface, execution modes, two-stage proof commits) that consumes these trust semantics. [`gate-core`](https://github.com/vorionsys/gate-core) is a separate repository whose README describes an implementation: a minimal deterministic engine that emits BASIS-family proof chains and points verification at [`@vorionsys/verify`](https://www.npmjs.com/package/@vorionsys/verify). Where a document in this repo and a document in basis-gate disagree on trust semantics, this repo is the authority for this project.

## Packages

| Package | In this repo | npm `latest` | What it is |
|---|---|---|---|
| [`@vorionsys/basis-spec`](packages/basis) | 1.3.0 | 1.3.0 | TypeScript parameters, formulas, constants, types, and proof-chain shape. Zod validators are a separate entry, `@vorionsys/basis-spec/zod`. No test script in this package. |
| [`@vorionsys/basis-spec-conformance`](packages/basis-conformance) | 0.5.0 | 0.5.0 | `basis-conformance run` self-tests this repo. `validate` is structural. `verify` / `verifyChain` checks RFC-0002 hashes, linkage, and Ed25519 signatures. |
| [`@vorionsys/basis-quorum`](packages/basis-quorum) | 0.1.0 | not published | Reference library for draft RFC-0005. |
| [`@vorionsys/basis-plan`](packages/basis-plan) | 0.1.0 | not published | Reference library for draft RFC-0006. |
| [`@vorionsys/basis-merkle`](packages/basis-merkle) | 0.1.0 | not published | Reference library for draft RFC-0007. |
| [`@vorionsys/basis-scorer`](packages/basis-scorer) | 0.1.1 | 0.1.1 | Recomputes a score and tier from a chain that was already validated elsewhere. |
| [`@vorionsys/basis-registry`](packages/basis-registry) | 0.1.0 | 0.1.0 | Library of offline primitives (self-certifying identifier, RFC 6962 log). It does not run a registry. |

`@vorionsys/basis-quorum`, `@vorionsys/basis-plan`, and `@vorionsys/basis-merkle` have no npm registry entry. Their package READMEs say to build them from this repository.

## RFCs

| # | Title | Status | In this repo |
|---|---|---|---|
| [0001](rfcs/0001-bot-package-manifest.md) | Bot Package Manifest v1 | Draft | Prose, [`0001-bot-package-manifest.schema.json`](rfcs/0001-bot-package-manifest.schema.json), and an example at [`rfcs/examples/aurais-market-scout.manifest.yaml`](rfcs/examples/aurais-market-scout.manifest.yaml). No package here parses or enforces manifests. |
| [0002](rfcs/0002-proof-event-chain.md) | Proof Event Chain v1 (document version 1.1) | Draft | Types in `@vorionsys/basis-spec`. Verifier, CLI, and vectors in `@vorionsys/basis-spec-conformance`. |
| [0003](rfcs/0003-conformance-attestation.md) | Conformance Attestation v1 | Draft | JSON Schema at [`schemas/attestation-v1.json`](schemas/attestation-v1.json), exercised by the conformance package. This repo does not publish a signed scorecard. |
| [0004](rfcs/0004-hash-suite-convergence.md) | Proof-Chain Hash-Suite Declaration & Convergence | Draft | Prose only. |
| [0005](rfcs/0005-quorum-authorization.md) | Quorum Authorization Events v1 | Draft | `@vorionsys/basis-quorum`. |
| [0006](rfcs/0006-plan-verification.md) | Execution Plan Verification v1 | Draft | `@vorionsys/basis-plan`. |
| [0007](rfcs/0007-compaction-selective-disclosure.md) | Chain Compaction and Selective Disclosure v1 | Draft | `@vorionsys/basis-merkle`. |

A comment in `packages/basis-conformance/src/index.ts` and the numbering note in RFC-0005 still call RFC-0004 a future vendor-endpoint spec. The file `rfcs/0004-hash-suite-convergence.md` is the hash-suite draft above. No vendor-endpoint mode is implemented in this repo.

## Why a shared definition

Runtime AI-agent governance needs interoperable primitives so that an agent
trusted by one platform can be evaluated by another, and so that compliance
auditors can read a single shared definition of "what does T5 mean."

BASIS is one attempt at that shared definition. It is intentionally narrow:
the texts fix parameters, formulas, and lifecycle semantics. They do
not choose a storage backend, a transport, or a proof system for an implementation.

## Governance

Changes are proposed as RFCs in this repo. `CHANGELOG.md` records package releases and some compatibility notes. It is not a separate backwards-compatibility or supply-chain policy.

[`.github/workflows/release.yml`](.github/workflows/release.yml) can publish a workspace package with `npm publish --provenance`. With no dist-tag flag, npm's default tag is `latest`. [`.github/workflows/prerelease.yml`](.github/workflows/prerelease.yml) is manual. Its package choices are `basis`, `basis-conformance`, and `basis-scorer`. It is written to publish `<version>-rc.<short git sha>` under the `next` dist-tag, also with `--provenance`. The leak-check step exits with an error unless a `leak-check` script exists, and no `package.json` in this repo defines one, so a dispatch stops before publish. Neither workflow retags `next` to `latest`.

## License

Apache-2.0 — see [LICENSE](LICENSE).

Anyone may build an implementation under any license they choose. The files in this repository are Apache-2.0.

## Other repositories

These projects are not in this tree. The rows describe their public READMEs and npm registry entries. Nothing here shows that they pass this repo's conformance suite.

| Project | What it is | Install |
|---|---|---|
| [`basis-gate`](https://github.com/vorionsys/basis-gate) | Separate spec and reference runtime. Published: `@vorionsys/basis-gate-spec` (layer interface, execution modes, two-stage commit — per that package's description), `@vorionsys/basis-gate-runtime`, `@vorionsys/basis-gate-industry`. [`examples/minimal-governance.ts`](https://github.com/vorionsys/basis-gate/blob/HEAD/examples/minimal-governance.ts) is labeled starter / reference use, not production. The file is written to allow a known agent, deny an unknown agent at the identity layer, and replay the events through that runtime's `verifyChain`. | Clone that repo and follow its README. The example imports the three packages above and is not in this repository. |
| [`gate-core`](https://github.com/vorionsys/gate-core) | Implementation, not a spec. npm package `@vorionsys/gate-core`. That README points chain checks at `@vorionsys/verify`. | `npm i @vorionsys/gate-core` |
| [`mcp-server`](https://github.com/vorionsys/mcp-server) | MCP server. Its README describes local trust checks and proof logging, and says the calling client decides whether to honor a result. The npm registry still serves `@vorionsys/mcp-server@0.3.2` (not marked deprecated). That same README says a clean public install does not start. | Build from that repository. This file does not treat `npm i @vorionsys/mcp-server` as a working setup. |
| [`sdk`](https://github.com/vorionsys/sdk) | TypeScript client. Its README describes registering an agent, requesting an action, reporting an outcome, and reading a trust score (local or remote). Peer dependency `@vorionsys/runtime` (npm `0.1.6`). That README does not document RFC-0002 chain emission or BASIS Gate verdicts. | `npm i @vorionsys/sdk @vorionsys/runtime` |
| [`vorion-find`](https://github.com/voriongit/vorion-find) | CLI that scans a machine for AI agents. `package.json` has no runtime dependencies. The license in that repo allows free use of a compiled binary and keeps the source proprietary. It is not Apache-2.0. The public npm registry has no `vorion-find` package. | Use that repository's own instructions. `npm i vorion-find` does not resolve. |
