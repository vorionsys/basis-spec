# `@vorionsys/basis-spec-conformance`

Self-tests for this repository, and a public verifier for RFC-0002 proof chains. `basis-conformance run` executes the tests in this package against `@vorionsys/basis-spec` and the RFC-0003 schema. `basis-conformance verify` checks a chain file. There is no live vendor-endpoint mode in this package (current version 0.5.0). A passing run is not a certification of another product.

It sits next to [`@vorionsys/basis-spec`](../basis) (the parameters) and [RFC-0003](../../rfcs/0003-conformance-attestation.md) (the scorecard format). RFC-0003 is Draft. This package does not sign or publish scorecards.

## What this ships

Three commands, with different jobs:

1. **The conformance suite** (`run`) — self-test mode. Runs against `@vorionsys/basis-spec` and `schemas/attestation-v1.json`. A passing run means these tests passed. It does not call a live runtime. Vendor-endpoint mode is not implemented. A comment in `src/index.ts` still says that mode would be specified as RFC-0004; the document at `rfcs/0004-hash-suite-convergence.md` is a different draft (hash-suite convergence).

2. **The public reference verifier** (`verify`, since 0.2.0) — cryptography, not self-test. Point it at a proof-chain JSON file and it recomputes the canonical bytes, re-derives `eventHash`/`eventHash3`, walks `previousHash` linkage, and checks detached Ed25519 signatures. `valid: true` means the record checks out. It is not a trust or compliance verdict.

3. **`validate`** — structural check of required RFC-0002 fields. It does not verify signatures or the hash chain.

## What's tested (161 tests, 11 files, at package 0.5.0)

Counted by `npm run build && npm test` in this repo. The checked-in `conformance-results.json` is an older run (87 tests) and is not that result. Test comments also name an "ATSF whitepaper"; that document is not in this repository, so those section numbers are not checked here. The constants under test live in `packages/basis/src/canonical.ts`.

| Suite | What it asserts | Spec ref |
|---|---|---|
| `canonical-params.test.ts` (22) | Published constants: trust-score range, gain rate, penalty ratios (3→10), 8 tiers, 6 risk levels, hysteresis, promotion delays | `packages/basis/src/canonical.ts` |
| `trust-formulas.test.ts` (14) | `gain = GAIN_RATE × ln(1+headroom) × ∛risk`, `loss = -P(T) × R × ln(1+C/2)`, `P(T) = 3+T` | `packages/basis/src/canonical.ts` |
| `proof-event-shape.test.ts` (17) | RFC-0002 schema validation: well-formed events pass, malformed events fail with clear paths, shadow-mode HITL refines work | [RFC-0002](../../rfcs/0002-proof-event-chain.md) |
| `proof-chain-linkage.test.ts` (8) | `previousHash[i] = eventHash[i-1]` across whole chain, broken links detected at first break | [RFC-0002 §"Verification"](../../rfcs/0002-proof-event-chain.md) |
| `canonical-serialization.test.ts` (12) | Sorted-key JSON, no whitespace, shortest decimals, idempotent canonicalization | [RFC-0002 §"Canonical serialization"](../../rfcs/0002-proof-event-chain.md) |
| `chain-verification.test.ts` (26) | End-to-end verification against golden vectors: valid signed chain, tampered payload, cut linkage, non-null head, corrupted signature, signature-domain mismatch, fail-closed posture | [RFC-0002 §"Verification procedure"](../../rfcs/0002-proof-event-chain.md) |
| `attestation-format.test.ts` (12) | RFC-0003 JSON Schema strict-mode validation, conditional requirements (revoked → revokedAt+reason; thirdParty → vendorAttestation) | [RFC-0003](../../rfcs/0003-conformance-attestation.md) |
| `canonical-known-answers.test.ts` (13) | Known answers for JSON canonicalization axes pinned in 0.5.0 | [RFC-0002 §"Canonical serialization"](../../rfcs/0002-proof-event-chain.md) |
| `expected-contract.test.ts` (29) | Vector files declare the outcome `verifyChain` must report (0.4.0) | [RFC-0002 §"Verification procedure"](../../rfcs/0002-proof-event-chain.md) |
| `manifest-validator.test.ts` (5) | `validateManifest` is structural only, including on a missing signature | [RFC-0002 §"Schema"](../../rfcs/0002-proof-event-chain.md) |
| `suite-meta.test.ts` (3) | `SUITE_VERSION` matches this package's `package.json` | this package |

## How to run

### From this repository

```bash
# From the repository root. `npm test` alone fails until @vorionsys/basis-spec is built:
# the suite imports that package from its dist/ entry.
npm install
npm run build
npm test
```

### As a conformance run with JSON output

```bash
npx basis-conformance run --out conformance-results.json --pretty
```

The output JSON is shaped to fit directly into the `results` field of an RFC-0003 attestation document.

### Verifying a proof chain (v0.2)

```bash
# Verify hashes, linkage, and Ed25519 signatures
npx basis-conformance verify chain.json --keys keys.json --pretty

# Verify hash + linkage integrity only (no keys available)
npx basis-conformance verify chain.json

# Make an unverifiable signature a hard failure
npx basis-conformance verify chain.json --require-signatures
```

`keys.json` is a map of `signedBy` identity → Ed25519 public key (PEM SPKI, 64-char hex, or base64 of the raw 32 bytes).

Try it against the shipped vectors — the valid chain exits `0`, every tampered variant exits `1`:

```bash
cd node_modules/@vorionsys/basis-spec-conformance
npx basis-conformance verify vectors/chain-valid-signed.json --keys vectors/keys.json
npx basis-conformance verify vectors/chain-tampered-payload.json --keys vectors/keys.json
```

**What a `valid: true` means and does not mean.** It means the record is intact: nothing was altered after sealing, the events form an unbroken chain from a null head, and the claimed signer produced them. It is **not** a trust score, a compliance verdict, or a statement that the agent behaved well. A cryptographically perfect chain of terrible decisions verifies just fine — that is what a receipt is for.

#### Golden vectors

`vectors/` ships `chain-valid-signed.json`, `chain-valid-unsigned.json`, and six failing chains: payload edit, cut linkage, non-null head, corrupted signature, signature-domain mismatch, and stripped signature. Regeneration is described as deterministic (fixed key seed, fixed timestamps) in `scripts/generate-vectors.mjs`.

They are generated by `scripts/generate-vectors.mjs`, which carries its **own independent implementation** of RFC-0002 §"Canonical serialization", written from the spec text rather than imported from the verifier. Sharing the implementation would make the tests circular; keeping them separate means a passing run proves two independent readings of the spec agree on the exact bytes. That byte agreement is the property every cross-vendor chain depends on.

#### Note on `signature`: RFC-0002 Erratum E-1

RFC-0002 v1.0/v1.1 was self-contradictory about what the detached signature covers — §"Schema" said `eventHash`, §"Verification procedure" said the canonical bytes. [Erratum E-1](../../rfcs/0002-proof-event-chain.md#changelog) resolves this in favor of the **canonical bytes**. The verifier defaults to that, accepts `--signature-domain eventHash` for chains sealed under the old reading, and when a signature fails under the active domain it retries under the other and reports `domain-mismatch` — so you get an actionable diagnostic instead of a bare "bad signature".

### From code

```ts
import { runConformance } from '@vorionsys/basis-spec-conformance/runner';
const results = await runConformance();
console.log(`${results.passed}/${results.total} tests passed`);
```

`runConformance()` rejects (throws) if the run discovers zero tests — an empty run is never returned as a passing result.

### Exit codes (CLI)

| Code | Meaning |
|---|---|
| `0` | `run`: all discovered tests passed (at least one test ran). `validate`: manifest structurally well-formed. `verify`: chain verified |
| `1` | `run`: one or more tests failed. `validate`: manifest has structural errors. `verify`: chain did not verify |
| `2` | Runner error: vitest could not be invoked, output could not be parsed, the manifest/chain/keys could not be read — or **zero tests were discovered** |

**Fail-closed guarantees.**

- A run that discovers zero tests never exits `0`. It prints an error to stderr and exits `2`, because "no tests ran" is indistinguishable from "the suite is missing" and must never be reported as conformance.
- An **empty chain is never a valid verification**. Same reasoning: nothing to verify is not the same as verified.
- A signature that is **present but could not be checked** — no key supplied, unusable key, malformed signature — is never silently counted as good. It is reported in `signaturesUnverified`, the CLI prints an explicit stderr note even when you did not ask for strict mode, and `--require-signatures` turns it into a failure.
- A **stripped signature always fails**, with or without `--require-signatures`. An event that names a signer in `signedBy` but carries no `signature` is reported as `'stripped'` and counted in `signaturesStripped`. This is deliberately *not* the same state as a legitimately unsigned event, which carries neither field and still verifies on hashes and linkage alone. Collapsing the two would let anyone downgrade a signed chain to an "unsigned" one by deleting a field — no key, no forgery, no hash work — and the hashes would still agree, because the signature is not part of the hash input. See `vectors/chain-stripped-signature.json`.
- `--require-signatures` means **every event must carry a signature that verified**. Unverifiable, stripped and absent all fail it.
- A **malformed public key is a hard error**, not a skipped check.

> **Changed in 0.3.0.** `--require-signatures` previously covered only the *present-but-unverifiable* case, so it accepted a chain carrying no signatures at all — the opposite of what the name promises. If you relied on the old behaviour to check hash and linkage integrity on unsigned chains, drop the flag: that is the default and still exits `0`.

### Suite revision

Every results document embeds `suite.revision`: the git commit sha of the source the build was cut from, stamped into the package at build time (`dist/revision.json`, written by `scripts/prepare-dist.mjs` from `GITHUB_SHA` in CI or `git rev-parse HEAD` locally). Unstamped local dev builds report `dev-build`. Verifiers should treat `dev-build` as untrusted and compare stamped revisions against known-good releases.

## How an attestation gets produced (forward look)

```text
1. Run conformance suite        → produces conformance-results.json
2. Embed in attestation doc     → adds product/version/releasedAt/etc.
3. Sign with release key        → Ed25519 signature over canonical JSON
4. Publish at well-known URL    → https://<product>/attestations/<v>.json
5. Buyer/auditor fetches + verifies signature + re-runs failing tests locally
```

This package does not include an attestation signing utility. `verify` checks signatures; it does not sign a scorecard.

## What later versions actually shipped

Package version is **0.5.0**. `CHANGELOG.md` stops at conformance 0.3.0. An older roadmap in this file said 0.3 would add vendor-endpoint mode, an RFC-0004 endpoint spec, and a signing utility, and that 0.4 would add property tests and pluggable profiles. Those items are not in the tree. Releases after 0.2, from the version bumps in git:

| Version | What landed |
|---|---|
| 0.2.0 | `verifyChain` and the `verify` CLI, golden vectors, exported canonicalizer, RFC-0002 Erratum E-1 |
| 0.3.0 | Stripped signatures fail; `--require-signatures` requires a signature that verified (`CHANGELOG.md`) |
| 0.4.0 | Machine-readable failure codes and the two-sided vector contract (`expected-contract.test.ts`) |
| 0.5.0 | JCS known-answer vectors (`canonical-known-answers.test.ts`) |

## Reporting issues / proposing tests

Open an issue at [vorionsys/basis-spec](https://github.com/vorionsys/basis-spec/issues). Test contributions welcome — additions to v0.x must cite a specific RFC section the test exercises.

## License

Apache-2.0 — see [LICENSE](LICENSE).
