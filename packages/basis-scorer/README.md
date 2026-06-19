# @vorionsys/basis-scorer

The **BASIS reference scorer** — a deterministic `evidence → score → tier` function with a
**fail-closed** authority binding. Built entirely on the canonical constants in
[`@vorionsys/basis-spec`](https://www.npmjs.com/package/@vorionsys/basis-spec).

This is the *Stage-3 reference function* that lets a trust tier **stop being a bare client input**.
A relying party recomputes the tier locally and binds the **lower** of the claim and its own
recomputation:

```
effectiveTier = verified
  ? min( claimed, recomputed, observationCeiling, localPolicyCeiling )
  : T0          // unverified / unmappable / unknown-observation → least privilege
```

## Why

Historically the gate only checked `claimedTier >= minimumTier`, trusting a client-supplied tier —
fail-open. This package makes the tier a **computed output**: pure integer/rational arithmetic over
the canonical 8-tier / 16-factor lattice, so any party recomputes a **byte-identical** result and a
divergence between *claimed* and *recomputed* makes the **lower** value bind.

## Install

```bash
npm install @vorionsys/basis-scorer @vorionsys/basis-spec
```

## Use

```ts
import { scoreTrust } from '@vorionsys/basis-scorer';

const result = scoreTrust({
  factorScores: { 'CT-COMP': 0.9, 'CT-REL': 0.8, /* … of the 16 canonical factors */ },
  observation: 'WHITE_BOX',   // observation tier → score ceiling + max reachable tier
  claimedTier: 'T6',          // optional client claim — coerced + min'd in
  verified: true,             // was the proof chain log-verified + re-derived?
});

result.compositeScore;          // mean over ALL 16 factors (missing → 0) × 1000
result.adjustedScore;           // min(composite, observation ceiling)
result.recomputedTier;          // tierFromScore(adjustedScore), e.g. 'T6'
result.effective.effectiveTier; // 'T6' — min(claimed, recomputed, ceiling, policy)
result.effective.binding;       // which term bound (or 'unverified' / 'unknown-observation')
```

Low-level pieces are exported too: `effectiveTier`, `toT`, the frozen `CAR_TO_T` / `T_TO_CAR`
projection, `OBS_MAXTIER` (derived from canonical `OBSERVATION_TIERS` — no drift), and
`computeCompositeScore`.

## Design rules (faithful to TIER_RECONCILIATION)

- **No inflation.** The composite averages over **all 16** canonical factors (a missing factor is 0),
  so you cannot raise your tier by omitting a weak one. (`@vorionsys/contracts` currently averages
  over *provided* factors — a gap this reference function deliberately closes.)
- **Fail closed.** Unverified, unmappable, or unknown-observation inputs → **T0**, never the claim.
- **Honest observation ceiling.** TEE verifiers are stubs today, so attested-execution claims cap at
  **WHITE_BOX (T6)** until a real quote verifier lands. `OBS_MAXTIER` is derived from the spec.
- **Frozen projection.** The legacy CAR-5 ⇄ T0–T7 table is frozen; coarsening (`T→CAR→T`) always
  rounds **down** — the safe direction for `min()`.

## Golden vectors

`@vorionsys/basis-scorer/golden-vectors` exports the canonical input→output pairs
(`CAR_PROJECTION_VECTORS`, `EFFECTIVE_TIER_VECTORS`, `COMPOSITE_VECTORS`) so a downstream conformance
suite can assert its build reproduces them. The test suite encodes the 11 tier-reconcile checks
(no-drift, projection, fail-closed effectiveTier) plus determinism.

```bash
npm test        # vitest
```

## License

Apache-2.0 — Copyright 2024-2026 Vorion LLC.
