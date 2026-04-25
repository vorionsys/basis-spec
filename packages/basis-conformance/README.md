# `@basis-spec/basis-conformance`

The official BASIS conformance test suite. Anyone — vendor, customer, auditor — can run this against the canonical spec or (in v0.2+) a live BASIS-compliant runtime endpoint and get a machine-readable report of which parts of the standard the implementation actually honors.

This package is the third leg of public-trust verification, alongside [`@basis-spec/basis`](../basis) (the spec) and [RFC-0003](../../rfcs/0003-conformance-attestation.md) (the signed scorecard format).

## v0.1 — what this ships

**Self-test mode only.** The suite runs against:

- `@basis-spec/basis` — the canonical TypeScript representation of the spec (constants, formulas, types, Zod validators)
- `schemas/attestation-v1.json` — the JSON Schema for RFC-0003 attestations

A passing run proves the spec is internally coherent and the canonical impl correctly implements it. It does **not** yet verify a live runtime endpoint — that's v0.2 (RFC-0004 will define the endpoints required).

## v0.1 — what's tested (≈40 tests across 6 suites)

| Suite | What it asserts | Spec ref |
|---|---|---|
| `canonical-params.test.ts` | All published constants match spec values: trust-score range, gain rate, penalty ratios (3→10), 8 tiers, 6 risk levels, hysteresis, promotion delays | ATSF whitepaper §4 |
| `trust-formulas.test.ts` | `gain = GAIN_RATE × ln(1+headroom) × ∛risk`, `loss = -P(T) × R × ln(1+C/2)`, `P(T) = 3+T` | ATSF whitepaper §5 |
| `proof-event-shape.test.ts` | RFC-0002 schema validation: well-formed events pass, malformed events fail with clear paths, shadow-mode HITL refines work | [RFC-0002](../../rfcs/0002-proof-event-chain.md) |
| `proof-chain-linkage.test.ts` | `previousHash[i] = eventHash[i-1]` across whole chain, broken links detected at first break | [RFC-0002 §"Verification"](../../rfcs/0002-proof-event-chain.md) |
| `canonical-serialization.test.ts` | Sorted-key JSON, no whitespace, shortest decimals, idempotent canonicalization | [RFC-0002 §"Canonical serialization"](../../rfcs/0002-proof-event-chain.md) |
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

### From code

```ts
import { runConformance } from '@basis-spec/basis-conformance/runner';
const results = await runConformance();
console.log(`${results.passed}/${results.total} tests passed`);
```

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
| **v0.1 (this release)** | Self-test mode, 6 test suites, CLI, JSON output, RFC-0003 result shape |
| v0.2 | Vendor-endpoint mode (point at a live BASIS runtime URL), RFC-0004 endpoint spec, signing utility |
| v0.3 | Property-based tests for canonical-serialization edge cases, golden-vector chain replay |
| v0.4 | Pluggable test profiles (minimal / strict / production) |
| v1.0 | Stable test ID namespace, public profile registry, third-party test contributions |

## Reporting issues / proposing tests

Open an issue at [vorionsys/basis-spec](https://github.com/vorionsys/basis-spec/issues). Test contributions welcome — additions to v0.x must cite a specific RFC section the test exercises.

## License

Apache-2.0 — see [LICENSE](LICENSE).
