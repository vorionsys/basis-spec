<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2024-2026 Vorion LLC
-->

# @vorionsys/basis-scorer

The **BASIS reference scorer** — a pure, deterministic, fail-closed function
that **re-computes** an agent's trust score and tier from a validated
proof-event chain (RFC-0002), so a client's *claimed* tier can only be
**lowered**, never raised.

> "Invert the artifact, not the trust." A claimed tier and any asserted
> `trust_delta` are treated as an **upper bound** and a **cross-check** — never
> as the source of truth. The scorer re-derives gain and loss from execution
> outcomes through the canonical [`@vorionsys/basis-spec`](../basis) formulas,
> which is what makes `effectiveTier = min(claimed, recomputed, caps)` real.

This package **reuses** the canonical constants and formulas from
`@vorionsys/basis-spec` (`calculateGain`, `calculateLoss`, `tierFromScore`,
`RISK_LEVELS`, `OBSERVATION_TIERS`, `CIRCUIT_BREAKER`, `RISK_ACCUMULATOR`, …).
It does **not** copy any constants.

---

## What it does

```ts
import { scoreChain } from '@vorionsys/basis-scorer';

const result = scoreChain(events /* ProofEvent[] */, {
  observationTier: 'GRAY_BOX',
  riskByActionType: { 'db.read': 'LOW', 'db.write': 'MEDIUM' },
  claimedTier: 'T5', // the client's assertion — an upper bound only
});

// result.recomputedScore   — independently re-derived score, [0,1000]
// result.recomputedTier     — tierFromScore(recomputedScore)
// result.effectiveTier      — min(recomputed, observation cap, policy cap, claimed)
// result.overClaim          — advisory: a claim exceeded the recomputed value
// result.divergences        — advisory evidence of claimed-vs-recomputed gaps
// result.policyHash         — SHA-256 of the (untrusted) policy used
```

`scoreChain` is a **pure function** over an **already structurally +
signature/linkage-validated** chain (validation is upstream, per the brief).
It still **fails closed** on anything it cannot compute.

### How a score is built

1. Start at `INITIAL_TRUST_SCORE` (0).
2. Sort events by their own `occurredAt` instant (then a causal-precedence
   tiebreak, then `eventId`). **No wall-clock is ever read.**
3. Replay in order:
   - `execution_completed(status:'success')` → `+calculateGain`.
   - `execution_failed` → `+calculateLoss` (negative) and a `P(T)·R`
     contribution to the rolling 24h risk accumulator.
   - `execution_completed(status:'partial')` → **zero gain** (fail closed; a
     partial success is not evidence of full competence).
   - `trust_delta` / `decision_made.trustScore` → **cross-check only**,
     never summed.
4. The **risk multiplier** for each outcome is resolved by walking
   `executionId → execution_started.decisionId → decision_made.intentId →
   intent_received.actionType`, then mapping the action type through the
   **policy** `riskByActionType`. Risk is **not in the chain** (see Limitations).
5. The result is capped: `effectiveTier = min(tierFromScore(score),
   observation-tier maxTier, policy ceiling, claimed tier)`, with a T0 floor
   when the circuit breaker is tripped.

---

## Determinism guarantee

The same chain + the same policy produce a **byte-identical** `ScoreResult` on
any platform.

- **All time is derived from `occurredAt`** — never `Date.now`. Timestamps are
  parsed by a pinned RFC-3339 parser to **exact BigInt nanoseconds** (offset
  normalised to UTC), so `…00.123456Z` and `…00.123Z` stay distinct and
  `…Z` and `…+05:30` for the same instant sort identically. Anything not
  losslessly representable (bare local time, sub-nanosecond precision, garbage)
  is rejected → fail closed.
- The running score is held as a **scaled integer (BigInt)** at a pinned
  precision (default `1e6`); each `calculateGain` / `calculateLoss` result is
  **quantized with round-half-even** before it is added, and the value fed back
  into the next `Math.log` / `Math.cbrt` is the **quantized** score — so the
  float input to libm is identical everywhere and the round-half-even on the
  output absorbs any last-ULP `log`/`cbrt` divergence.
- The fold is **strictly sequential** (no reassociation / parallel reduce).
- A true `(instant, eventId)` tie is **rejected** (non-deterministic ordering).

> **Residual risk (honest):** `Math.log` / `Math.cbrt` are not guaranteed
> bit-identical across libm implementations. The round-half-even quantization at
> `1e6` is designed to absorb the last ULP, and a long-chain stability test
> guards it, but a sufficiently exotic libm could in principle escape the
> quantization. Tighten `precision` and run the cross-platform check on the
> target platform if this matters to you.

## Fail-closed guarantee

Any malformed, unverifiable, unknown, or non-deterministic input degrades
toward **least privilege** (T0 / `FAIL_CLOSED`), never toward the higher value:

- Unknown / unmapped `actionType`, or a broken risk link → `defaultRisk`
  (default `LIFE_CRITICAL`, multiplier 30): cheap gain impossible, failure
  maximally penalised.
- Unknown observation tier → most restrictive (`BLACK_BOX`: ceiling 600 /
  maxTier T3) + flag.
- `ATTESTED_BOX` / `VERIFIED_BOX` **without** `assertVerifiedObservation` →
  downgraded to `WHITE_BOX` (TEE verifiers are stubs ecosystem-wide; we never
  assume a higher observation tier on trust).
- Unparseable `occurredAt`, missing `eventId`, invalid `precision`,
  malformed `claimedTier`/`ceilingTier`, or a `(instant, eventId)` tie →
  `FAIL_CLOSED` with `error` set.
- Any residual throw (e.g. a corrupted ceiling driving NaN/Infinity, or
  `tierFromScore` out of range) is caught → `FAIL_CLOSED` T0.
- A **missing** `claimedTier` imposes **no** client upper bound (it is **not**
  defaulted to T7); the observation/policy caps still apply. A claim can only
  ever lower the result.

---

## What `overClaim` / `divergences` actually mean (no over-statement)

The divergence cross-check compares the runtime's claimed numbers
(`trust_delta.newScore`, `decision_made.trustScore`) to the scorer's running
recomputed value and flags gaps. **This is advisory evidence, not enforcement.**
A sophisticated runtime controls its own claimed numbers and can make
`claimed == recomputed` to evade the flag while still asserting a high
`claimedTier` at the API boundary.

The actual defence against over-claim is **`effectiveTier = min(...)`** — the
client's claim is an upper bound the recomputation can only lower. Do not read
`overClaim` as "the scorer caught the lie"; read it as "the claimed and
recomputed values diverged here."

`recomputedScore` is a **quantized fixed-precision decimal in [0, 1000]** (e.g.
`200.265`), **not** an integer.

---

## v0.1 scope

**In scope (implemented faithfully):**

- Pure deterministic fold over a validated `ProofEvent[]` →
  `{ recomputedScore, recomputedTier, observationCappedTier, effectiveTier,
  status, circuitBreaker, riskAccumulator24h, divergences, overClaim, flags,
  scoredEventCount, policyHash }`.
- Gain on `execution_completed(success)` and loss on `execution_failed` via the
  canonical `calculateGain` / `calculateLoss` (no copied constants).
- Risk resolution by linkage walk + explicit policy map, fail-closed to max.
- Observation ceiling: drives gain headroom; caps `effectiveTier`; honest
  `WHITE_BOX` cap for stubbed TEE.
- Circuit breaker (tripped / degraded) **with a has-qualified latch** (see
  below) and the rolling 24h risk accumulator over `occurredAt`.
- Recompute-vs-claimed cross-check (advisory) and `effectiveTier = min(...)`.
- `shadowMode` exclusion (`shadow` / `testnet` excluded from production
  accounting; `production` / `verified` / absent move the score).
- Golden vectors + determinism + fail-closed + recompute tests.

### Circuit-breaker semantics (the fresh-agent latch)

`CIRCUIT_BREAKER.trippedThreshold` (100) and `degradedThreshold` (200) sit
**above** `INITIAL_TRUST_SCORE` (0). A naive "score < 100 ⇒ tripped" rule would
brick **every fresh agent at birth** and freeze the very gains it needs to climb
past `QUALIFICATION_PASS_SCORE` (200). That is a logic bug, not a safe failure.

This scorer therefore distinguishes **climbing** from **falling**: the
score-path circuit breaker engages **only after** the recomputed score has
crossed `QUALIFICATION_PASS_SCORE` (200) at least once during the replay (a
`hasQualified` latch derived purely from the events). A fresh agent climbing
from 0 is treated as provisioning, not as a tripped agent. The **risk
accumulator** path can still trip/degrade regardless of qualification (a burst
of failures is always a safety signal that can only lower trust).

### Deferred to v0.2 (explicitly, not silently omitted)

- **`PROMOTION_DELAYS` (T5–T7 time-gating).** Day-granularity promotion holds
  need a "sustained behaviour" window the events do not cleanly express (no
  promotion-eligibility marker). v0.1 computes `tierFromScore` but does **not**
  enforce high-tier promotion delays.
- **`DORMANCY` half-life / idle deductions.** Requires a defined "now" to
  measure idleness; deriving it from the last event vs an evaluation instant
  reintroduces wall-clock non-determinism. Out of scope; the scorer scores only
  the evidence present.
- **`HYSTERESIS` demotion buffers.** A stateful cross-evaluation tier-transition
  smoother, not a pure function of one chain. v0.1 returns the raw, non-sticky
  `tierFromScore`.
- **Numeric `incident_detected` / `rollback_initiated` weighting.** No canonical
  formula maps incident severity or rollback to a score delta; inventing one
  would over-claim. v0.1 treats them as **safety / accumulator flags that can
  only hold-or-lower**.
- **`partial` fractional credit.** Treated as **zero gain** in v0.1; any
  partial-credit curve needs a canonical definition first.
- **Cryptographic chain / signature verification.** Out of scope by design — the
  scorer is a pure function over an already-validated chain. It still fails
  closed on anything it cannot compute.

---

## Limitations (read before relying on this)

- **Risk is not in the signed chain.** `execution_completed` /
  `execution_failed` carry no `RiskLevel`, and `intent_received.actionType` is a
  free-form string. Risk is resolved only through the **caller-supplied**
  `policy.riskByActionType`. The same party that asserts the tier therefore
  controls the risk multiplier (hence gain/loss magnitude) and the observation
  cap (`assertVerifiedObservation`). **Risk integrity depends on policy
  integrity, which is out of the signed chain.** To make this reproducible and
  attributable, the exact policy is hashed into `result.policyHash`. We
  recommend a follow-up (RFC-0002.1) that puts a **signed** risk field in
  `intent_received` (or `decision_made`) so risk becomes part of the evidence.
- **`execution_started` must precede an outcome** for risk to resolve. If a
  runtime omits it, the `executionId → decisionId → intentId → actionType`
  link is unrecoverable and risk fails closed to max (and the outcome is
  flagged `broken_link_risk_maxed`).
- **The divergence flag is advisory, not enforcement** (see above).

No "trustless", "production-ready", or "full BASIS scoring" claims are made.
This is the **core**, implemented faithfully, with the temporal mechanics above
explicitly deferred.

---

## API

```ts
type RiskKey =
  | 'READ' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'LIFE_CRITICAL';

interface ScoringPolicy {
  observationTier: ObservationTier;                  // governs ceiling + maxTier
  riskByActionType: Readonly<Record<string, RiskKey>>;
  defaultRisk?: RiskKey;                             // default 'LIFE_CRITICAL'
  ceilingTier?: TrustTier;                           // optional hard policy cap
  assertVerifiedObservation?: boolean;               // default false; gates ATTESTED/VERIFIED
  precision?: number;                                // pinned quantization scale, default 1e6
  claimedTier?: TrustTier;                           // client's claim — upper bound only
}

interface Divergence {
  eventId: string;
  kind: 'trust_delta' | 'decision_score';
  claimed: number;
  recomputed: number;
}

interface ScoreResult {
  recomputedScore: number;        // quantized fixed-precision decimal in [0,1000]
  recomputedTier: TrustTier;
  observationCappedTier: TrustTier;
  effectiveTier: TrustTier;       // min(recomputed, obs cap, policy cap, claimed)
  status: 'OK' | 'DEGRADED' | 'TRIPPED' | 'FAIL_CLOSED';
  circuitBreaker: 'NONE' | 'DEGRADED' | 'TRIPPED';
  riskAccumulator24h: number;
  divergences: ReadonlyArray<Divergence>;
  overClaim: boolean;             // advisory only — see note above
  flags: ReadonlyArray<string>;
  scoredEventCount: number;
  policyHash: string;             // SHA-256 of the canonical-JSON policy used
  error?: string;                 // set when status === 'FAIL_CLOSED'
}

/** Pure, deterministic. Input chain MUST be already validated upstream. */
function scoreChain(events: ReadonlyArray<ProofEvent>, policy: ScoringPolicy): ScoreResult;

/** Convenience: recompute then min against a claimed tier. Never raises. */
function effectiveTier(result: ScoreResult, claimed?: TrustTier): TrustTier;
```

## License

Apache-2.0. Copyright 2024-2026 Vorion LLC.
