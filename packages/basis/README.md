# @basis-spec/basis

> **BASIS** — Baseline Authority for Safe & Interoperable Systems.
> Open standard for AI agent trust and governance.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![npm](https://img.shields.io/npm/v/@basis-spec/basis)](https://www.npmjs.com/package/@basis-spec/basis)

This package is the canonical TypeScript representation of the BASIS spec.
It exports the tier definitions, risk levels, formulas, and constants any
conforming implementation can rely on.

## What BASIS defines

- **An 8-tier trust score model (T0..T7)** on a 0..1000 scale, with each tier specifying its score range and intended autonomy level.
- **Six risk levels** (READ, LOW, MEDIUM, HIGH, CRITICAL, LIFE_CRITICAL) with multipliers used in trust update formulas and minimum trust thresholds for action gating.
- **A logarithmic gain formula** with cube-root risk scaling to prevent risk-seeking as a path to faster trust accumulation.
- **An asymmetric loss formula** with tier-scaled penalty multipliers `P(T) = 3 + T`, anchored to a fixed midpoint reference so loss exposure cannot be reduced by positioning near the ceiling.
- **Five observation tiers** capping the maximum achievable score based on internal-state visibility.
- **A risk accumulator** with rolling 24-hour windows for warning, degraded, and circuit-breaker thresholds.
- **A dormancy schedule** with stepped per-milestone deductions for inactive agents and a 50% floor.
- **Eight lifecycle states** every agent traverses, with explicit `canOperate / canGain / canLose` semantics per state.
- **A no-positive-inheritance rule**: derived agents start at zero trust and earn it.

## Install

```bash
npm install @basis-spec/basis
```

## Use the canonical values

```typescript
import {
  TRUST_TIERS,
  RISK_LEVELS,
  OBSERVATION_TIERS,
  GAIN_RATE,
  PENALTY_RATIO_MIN,
  PENALTY_RATIO_MAX,
  HYSTERESIS,
  PROMOTION_DELAYS,
  CIRCUIT_BREAKER,
  RISK_ACCUMULATOR,
  DORMANCY,
  LIFECYCLE_STATES,
  BASIS_SPEC_VERSION,
} from '@basis-spec/basis';

console.log(BASIS_SPEC_VERSION); // "1.0.0"
```

## Helper functions

```typescript
import {
  tierFromScore,
  penaltyRatio,
  calculateGain,
  calculateLoss,
} from '@basis-spec/basis';

tierFromScore(750);       // "T4"
penaltyRatio(0);          // 3
penaltyRatio(7);          // 10

calculateGain({ currentScore: 500, ceiling: 900, riskMultiplier: 5 });
// 0.05 * ln(401) * cbrt(5)

calculateLoss({ tierIndex: 4, ceiling: 900, riskMultiplier: 10 });
// -7 * 10 * 0.05 * ln(451)
```

## Zod validators (optional)

```typescript
import {
  AgentTrustStateSchema,
  GateDecisionSchema,
} from '@basis-spec/basis/zod';

const result = AgentTrustStateSchema.safeParse(input);
if (!result.success) console.error(result.error.format());
```

## Conformance

Any implementation that imports from this package and respects the canonical
values is considered BASIS-conforming at the parameter level. To verify
behavioural conformance (formulas, tier transitions, lifecycle invariants),
use the companion test-vector package:

```bash
npm install --save-dev @basis-spec/basis-conformance
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
