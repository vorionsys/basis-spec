# BASIS Spec

[![CI](https://github.com/vorionsys/basis-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/vorionsys/basis-spec/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@vorionsys/basis-spec.svg)](https://www.npmjs.com/package/@vorionsys/basis-spec)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Baseline Authority for Safe & Interoperable Systems** — an open standard for AI agent trust and governance.

> **Versioning note:** the BASIS *standard* is at revision **0.9** (working draft; 1.0 ratification targeted 2027). npm package versions (e.g. `@vorionsys/basis-spec@1.2.x`) track this TypeScript distribution, not the standard revision.

> **One standard, and how the gate artifacts relate:** **BASIS** (this repo) is the standard — canonical trust parameters, formulas, types, and the proof-chain RFCs. **BASIS Gate** ([`basis-gate`](https://github.com/vorionsys/basis-gate)) is a *companion specification under the BASIS umbrella* covering governance-pipeline composition (layer interface, execution modes, two-stage proof commits); it consumes BASIS trust semantics and does not redefine them. **[`gate-core`](https://github.com/vorionsys/gate-core)** is an *implementation*, not a spec — a minimal deterministic engine producing RFC-0002 proof chains. If a document here and one in basis-gate ever disagree on trust semantics, this repo wins.

## Packages

| Package | Description |
|---|---|
| [`@vorionsys/basis-spec`](packages/basis) | Canonical TypeScript representation of the spec — tiers, risk levels, formulas, constants, types, optional Zod validators, **proof-chain shape**. |
| [`@vorionsys/basis-spec-conformance`](packages/basis-conformance) | Self-test vectors that check the spec is internally coherent, plus a truth-only structural validator (`validateManifest` / `basis-conformance validate <manifest.json>`) that checks an external proof-chain manifest for RFC-0002 required-field presence and basic shape. Structural checks only — it reports missing/malformed fields and emits no trust, compliance, or conformance verdict, and does not verify signatures or the hash chain. |

## RFCs

| # | Title | Status |
|---|---|---|
| [0001](rfcs/0001-bot-package-manifest.md) | Bot Package Manifest v1 | Draft |
| [0002](rfcs/0002-proof-event-chain.md) | Proof Event Chain v1 — the public shape of every audit event a BASIS-compliant runtime emits, plus the hash-chain rules that make it tamper-evident. | Draft |
| [0003](rfcs/0003-conformance-attestation.md) | Conformance Attestation v1 — signed scorecard each BASIS-compliant product publishes per release. JSON Schema at [`schemas/attestation-v1.json`](schemas/attestation-v1.json). | Draft |

## Why an open standard

Runtime AI-agent governance needs interoperable primitives so that an agent
trusted by one platform can be evaluated by another, and so that compliance
auditors can read a single shared definition of "what does T5 mean."

BASIS is one attempt at that shared definition. It is intentionally narrow:
the standard fixes parameters, formulas, and lifecycle semantics. It does
**not** dictate which storage backend, transport protocol, or proof system
an implementation must use.

## Governance

BASIS evolves through a public RFC process (this repo) governed by Vorion's umbrella realities. Backwards-compatibility within a major version, deprecation discipline, and supply-chain integrity rules are mirrored here and in CHANGELOG.md.

Pre-publish sharing (`*-rc.<sha>` tags on npm) goes through the published prerelease workflow at `.github/workflows/prerelease.yml` — gated by build, leak-check, test, and provenance. Pre-release versions ship with the `next` dist-tag and are never promoted silently to `latest`.

## License

Apache-2.0 — see [LICENSE](LICENSE).

Anyone may build conforming or non-conforming implementations under any
license they choose; this repository's contents are themselves Apache-2.0.

## Implementations & Integrations

BASIS is a specification. The packages below implement it or build on it. The `@vorionsys/basis-gate-*` packages are the reference for the layer interface, execution modes, and the two-stage proof-chain commit protocol.

| Project | What it is | Install |
|---|---|---|
| [`basis-gate`](https://github.com/vorionsys/basis-gate) | Reference runtime for BASIS Gate v1 — posture resolver, block/inline/deferred executor, Ed25519 two-stage proof chain, and reference layers (identity, tier-check, rate-limit, proof-chain-tip, audit-log). | `npm i @vorionsys/basis-gate-runtime @vorionsys/basis-gate-industry` |
| [`mcp-server`](https://github.com/vorionsys/mcp-server) | Model Context Protocol server that wraps tool calls in a BASIS Gate pipeline so an MCP client's actions are governed and proof-chained. | `npm i @vorionsys/mcp-server` |
| [`vorion-find`](https://github.com/voriongit/vorion-find) | Zero-dep CLI that scans a device for AI agents and streams findings (proprietary; binary free to use — not Apache-2.0). | CLI — run from the repo (`npx` / download); not a library |
| [`sdk`](https://github.com/vorionsys/sdk) | TypeScript client for building agents that emit BASIS-conformant actions and consume gate verdicts. | `npm i @vorionsys/sdk` |

**Run the reference runtime in ~50 lines** — a known agent's action is allowed and proof-chained; an unknown agent is denied by the identity rule; each verdict emits a signed proof-chain tip. See [`examples/minimal-governance.ts`](https://github.com/vorionsys/basis-gate/blob/HEAD/examples/minimal-governance.ts) (starter / reference use, not production-hardened):

```bash
npm i @vorionsys/basis-gate-runtime @vorionsys/basis-gate-industry @vorionsys/basis-gate-spec
npx tsx examples/minimal-governance.ts
```

> **Starter / reference** implementations — they illustrate the spec and are scaffolding for production deployments, not feature-complete layers (content-safety, jailbreak-detection, durable deferred-queue storage, and third-party-layer sandboxing are out of scope for the reference runtime).
