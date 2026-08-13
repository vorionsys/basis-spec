# `@vorionsys/basis-spec-conformance`

The official BASIS conformance test suite **and the public reference verifier for RFC-0002 proof chains**. Anyone — vendor, customer, auditor — can run the suite against the canonical spec and get a machine-readable report of which parts of the standard the implementation actually honors, and can independently verify any runtime's proof chain with `basis-conformance verify`. Live-endpoint mode arrives in v0.3.

This package is the third leg of public-trust verification, alongside [`@vorionsys/basis-spec`](../basis) (the spec) and [RFC-0003](../../rfcs/0003-conformance-attestation.md) (the signed scorecard format).

## What this ships

Two things, with different jobs:

1. **The conformance suite** (`run`) — self-test mode. Runs against `@vorionsys/basis-spec` (the canonical TypeScript representation of the spec) and `schemas/attestation-v1.json` (the RFC-0003 attestation schema). A passing run proves the spec is internally coherent and the canonical impl correctly implements it. It does not yet drive a live runtime endpoint — that's the vendor-endpoint mode still to come (RFC-0004 will define the endpoints required).

2. **The public reference verifier** (`verify`, new in v0.2) — cryptography, not self-test. Point it at *any* runtime's proof chain and it recomputes the canonical bytes, re-derives `eventHash`/`eventHash3`, walks `previousHash` linkage, and checks detached Ed25519 signatures. This is the piece that lets a buyer or auditor verify a BASIS chain **without vendor tooling and without reading proprietary source**.

## What's tested (110 tests across 7 suites)

| Suite | What it asserts | Spec ref |
|---|---|---|
| `canonical-params.test.ts` | All published constants match spec values: trust-score range, gain rate, penalty ratios (3→10), 8 tiers, 6 risk levels, hysteresis, promotion delays | ATSF whitepaper §4 |
| `trust-formulas.test.ts` | `gain = GAIN_RATE × ln(1+headroom) × ∛risk`, `loss = -P(T) × R × ln(1+C/2)`, `P(T) = 3+T` | ATSF whitepaper §5 |
| `proof-event-shape.test.ts` | RFC-0002 schema validation: well-formed events pass, malformed events fail with clear paths, shadow-mode HITL refines work | [RFC-0002](../../rfcs/0002-proof-event-chain.md) |
| `proof-chain-linkage.test.ts` | `previousHash[i] = eventHash[i-1]` across whole chain, broken links detected at first break | [RFC-0002 §"Verification"](../../rfcs/0002-proof-event-chain.md) |
| `canonical-serialization.test.ts` | Sorted-key JSON, no whitespace, shortest decimals, idempotent canonicalization | [RFC-0002 §"Canonical serialization"](../../rfcs/0002-proof-event-chain.md) |
| `chain-verification.test.ts` | **(v0.2)** End-to-end verification against golden vectors: valid signed chain, tampered payload, cut linkage, non-null head, corrupted signature, signature-domain mismatch, fail-closed posture | [RFC-0002 §"Verification procedure"](../../rfcs/0002-proof-event-chain.md) |
| `attestation-format.test.ts` | RFC-0003 JSON Schema strict-mode validation, conditional requirements (revoked → revokedAt+reason; thirdParty → vendorAttestation) | [RFC-0003](../../rfcs/0003-conformance-attestation.md) |

## How to run

### Quickly (vitest direct)

```bash
cd packages/basis-conformance
npm install
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

`vectors/` ships a valid signed chain plus five tampered variants (payload edit, cut linkage, non-null head, corrupted signature, signature-domain mismatch) and an unsigned chain. They are deterministic — fixed key seed, fixed timestamps — so regeneration produces byte-identical files.

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

A signing utility ships with v0.2; for v0.1 you can pipe the results JSON into your own signing pipeline.

## Roadmap

| Version | Adds |
|---|---|
| v0.1 | Self-test mode, 6 test suites, CLI, JSON output, RFC-0003 result shape |
| **v0.2 (this release)** | **Public reference verifier** (`verifyChain` + `verify` CLI): canonical-byte recomputation, sha256/sha3-256, linkage walk, Ed25519 signature checking. Golden vectors with an independent canonicalizer. Exported canonicalizer for vendor impls. RFC-0002 Erratum E-1 |
| v0.3 | Vendor-endpoint mode (point at a live BASIS runtime URL), RFC-0004 endpoint spec, attestation signing utility |
| v0.4 | Property-based tests for canonical-serialization edge cases; pluggable test profiles (minimal / strict / production) |
| v1.0 | Stable test ID namespace, public profile registry, third-party test contributions |

## Reporting issues / proposing tests

Open an issue at [vorionsys/basis-spec](https://github.com/vorionsys/basis-spec/issues). Test contributions welcome — additions to v0.x must cite a specific RFC section the test exercises.

## License

Apache-2.0 — see [LICENSE](LICENSE).
