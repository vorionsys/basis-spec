# RFC-0008: Risk-Weighted Gain

**Status:** Draft
**Version:** 0.2
**Date:** 2026-11-21
**Author:** Vorion LLC
**Related:** `packages/basis/src/canonical.ts` (gain and loss formulas, `RISK_LEVELS`, `RISK_ACCUMULATOR`), CAR ID

---

## Summary

Trust gain today depends mostly on **how many** successes an agent logs, not on **what they prove**. An agent that runs 2,000 low-stakes reads a day reaches T5 in two days under the current formulas. An agent that moves money five times a day needs more than a year.

This RFC proposes four changes, which work together:

1. **A per-action gain coefficient `k(a)`** set by a risk factor `ρ(a)`, bounded to [0.05, 0.25], a 5x spread whose floor is today's `GAIN_RATE`. It replaces `GAIN_RATE × ∛R` in the gain formula.
2. **Loss charged on the same `k(a)`**, so the break-even success rate depends on tier and score position only, not on the risk mix.
3. **An evidence ceiling**: an agent cannot score above the ceiling for the highest risk level at which it has demonstrated evidence.
4. **Volume normalisation**: within a 24-hour window, events beyond a fixed count per risk level carry proportionally less weight, on gains and losses alike.

It also binds the agent-class risk prior to CAR ID, defines what happens on a class change, and adds a severe-failure demotion rule. Item 2 makes high-risk failures much cheaper in score terms. The severe-failure rule and the existing risk accumulator take over that role (§5.6).

**Invariant.** Risk weighting changes **time-to-tier**. It does not change tier boundaries, `TRUST_THRESHOLDS_BY_RISK`, `P(T)`, hysteresis, promotion delays or observation ceilings. The evidence ceiling (§5.4) is the one place this RFC changes what a tier implies, and it makes that meaning **stricter and uniform**: T4 and above imply demonstrated MEDIUM-level evidence, T5 and above HIGH, and T7 CRITICAL.

No formula changes with this draft. `canonical.ts` gains one non-normative object, `PROPOSED_RFC_0008`, that no function reads.

---

## 1. How the formulas behave today

From `canonical.ts`:

```
gain = GAIN_RATE × ln(1 + C − S) × ∛R          GAIN_RATE = 0.05
loss = −P(T) × R × GAIN_RATE × ln(1 + C/2)     P(T) = 3 + T
```

The loss is **neither fixed nor proportional to that action's gain**. Both share `GAIN_RATE` and both use `R`, but gain takes `∛R` and the headroom term `ln(1 + C − S)`, while loss takes `R` linearly and a fixed midpoint `ln(1 + C/2)`. The realised loss-to-gain ratio is therefore:

```
loss/gain = P(T) × R^(2/3) × m(S),    m(S) = ln(1 + C/2) / ln(1 + C − S)
```

The stated 3x to 10x penalty curve is the loss-to-gain ratio **only for a READ action at the score where headroom equals C/2**. Everywhere else the ratio is higher, and it grows with risk:

| Level | Tier | S | Ratio today | Break-even today | Loss (points) today |
|---|---|---|---|---|---|
| READ | T0 | 100 | 2.74 | 73.3% | 0.93 |
| LOW | T1 | 250 | 7.81 | 88.7% | 3.73 |
| MEDIUM | T3 | 550 | 17.85 | 94.7% | 9.32 |
| HIGH | T4 | 700 | 35.39 | 97.3% | 21.76 |
| CRITICAL | T5 | 820 | 58.19 | 98.3% | 37.30 |
| LIFE_CRITICAL | T7 | 960 | 161.63 | 99.4% | 93.25 |

C = 1000 throughout. Reproduce with `node rfcs/examples/0008-model.mjs`.

The `∛R` versus `R` asymmetry is deliberate ("preventing risk-seeking behaviour as a path to faster gain"), and so is the midpoint reference (it stops agents parking near the ceiling to shrink their loss exposure). This RFC keeps the second and replaces the first with gating plus the evidence ceiling (§6).

**Public claims.** Under today's formulas, "failures cost 3x to 10x a success" is true only for READ actions at the midpoint score. Documentation, sites and marketing should not quote the 3x to 10x ratio as a general property until loss and gain are reconciled, whether by this RFC or another change. The accurate statement today is that the penalty multiplier P(T) runs from 3 at T0 to 10 at T7.

`@vorionsys/contracts` documents the same two formulas (`pre-action-gate.ts`) with `gainRate` defaulting to 0.01 instead of 0.05. That divergence is a separate finding; this RFC does not resolve it.

---

## 2. Motivation

A flat rate rewards volume. Under today's formulas:

| Agent | Profile | T3 | T4 | T5 |
|---|---|---|---|---|
| L | 2,000/day, 80% READ, 20% LOW, 99.5% success | day 1 | day 2 | day 2 |
| H | 5/day, highest permitted level up to HIGH, 99% success | day 260 | day 330 | day 409 |

L never demonstrates anything above LOW, yet it outranks H, which has done hundreds of gated MEDIUM and HIGH actions. For a certification scheme whose claim is that "T4" means the same thing everywhere, that is the wrong ordering.

---

## 3. Why bounding the rate alone does not fix it

The obvious fix, a per-action rate bounded to 0.01..0.05, does not change the ordering. A 5x rate spread cannot offset a 400x volume difference:

| Configuration | L: T3 / T4 / T5 | H: T3 / T4 / T5 |
|---|---|---|
| Today | 1 / 2 / 2 | 260 / 330 / 409 |
| k ∈ [0.01, 0.05], rate only | 4 / 5 / 7 | 1,155 / 1,355 / 1,528 |
| k ∈ [0.05, 0.25], rate only | 1 / 2 / 2 | 232 / 272 / 306 |

The 0.01..0.05 range also slows every agent 2.5x to 5x relative to today, because today's effective coefficient `0.05 × ∛R` already runs from 0.05 to 0.155. Agent H would need about 3.7 years to reach T4.

Volume is the problem, so the fix has to act on volume. That is what the evidence ceiling and normalisation do (§5.4, §5.5).

---

## 4. Terminology

- **Risk level**: one of `RISK_LEVELS` (READ … LIFE_CRITICAL), unchanged.
- **Risk factor ρ(a)**: a number in [0, 1] for action `a`, derived from its risk level (§5.1).
- **Gain coefficient k(a)**: `GAIN_RATE_MIN + ρ(a) × (GAIN_RATE_MAX − GAIN_RATE_MIN)`.
- **Enforcement point**: the component that gates the action and emits its proof event (for example, a CogniGate deployment).
- **Agent class**: a certifier-assigned category bound to the agent's CAR ID. Its only effect is a default risk level for actions the enforcement point cannot classify (§5.7).

---

## 5. Proposal

### 5.1 Risk factor

| Level | ρ | k(a) with [0.05, 0.25] | k(a) with [0.01, 0.05] |
|---|---|---|---|
| READ | 0 | 0.050 | 0.010 |
| LOW | 0.15 | 0.080 | 0.016 |
| MEDIUM | 0.35 | 0.120 | 0.024 |
| HIGH | 0.6 | 0.170 | 0.034 |
| CRITICAL | 0.85 | 0.220 | 0.044 |
| LIFE_CRITICAL | 1.0 | 0.250 | 0.050 |

- The **enforcement point** MUST assign ρ from the action's declared effects. The agent MUST NOT supply it.
- The enforcement point MAY raise ρ by at most **one level step** (to the next level's value) for irreversibility or blast radius. It MUST NOT lower ρ below the base value for the level.
- The proof event for the action MUST record the level, any step-up, and the inputs that justified it, so a verifier can re-derive `k(a)`.

`RISK_LEVELS` descriptions already encode reversibility ("Minor, reversible", "Severe, hard to reverse"). Uncapped modifiers would count it twice and hand the classifier a dial. The one-step cap bounds that.

### 5.2 Gain

```
gain = k(a) × ln(1 + C_eff − S) × w
```

`C_eff` comes from §5.4 and `w` from §5.5. The `∛R` term is removed, because `k(a)` now carries the risk weighting.

### 5.3 Loss

```
loss = −P(T) × k(a) × ln(1 + C/2) × w
```

`C` here is the **observation** ceiling, not `C_eff`, so an agent cannot lower its loss reference by staying out of high-risk work.

With the same `k(a)` and `w` on both sides, the ratio becomes:

```
loss/gain = P(T) × m(S)
```

The break-even success rate is then `P·m / (P·m + 1)`. It depends on tier and score position only. At the reference point (headroom = C/2), `m = 1` and the break-even is exactly `r/(r+1)`: 75% at T0 and 90.9% at T7. Above the reference, `m > 1`, so the break-even tightens as an agent approaches its ceiling. That is the existing anti-parking property, kept deliberately.

| Level | Tier | S | Ratio proposed | Break-even proposed | Loss (points) proposed |
|---|---|---|---|---|---|
| READ | T0 | 100 | 2.74 | 73.3% | 0.93 |
| LOW | T1 | 250 | 3.76 | 79.0% | 1.99 |
| MEDIUM | T3 | 550 | 6.10 | 85.9% | 4.48 |
| HIGH | T4 | 700 | 7.62 | 88.4% | 7.40 |
| CRITICAL | T5 | 820 | 9.57 | 90.5% | 10.94 |
| LIFE_CRITICAL | T7 | 960 | 16.74 | 94.4% | 15.54 |

**Cost of this choice.** A HIGH failure at T4 costs 7.4 points instead of 21.8, and a LIFE_CRITICAL failure at T7 costs 15.5 instead of 93.3. Score movement stops being the main brake on severe failures. §5.6 supplies that brake.

### 5.4 Evidence ceiling

```
C_eff = min(C_observation, EVIDENCE_CEILING[highest demonstrated level])
```

| Highest demonstrated level | Ceiling | Highest reachable tier |
|---|---|---|
| READ | 499 | T2 |
| LOW | 649 | T3 |
| MEDIUM | 799 | T4 |
| HIGH | 950 | T6 |
| CRITICAL | 1000 | T7 |
| LIFE_CRITICAL | 1000 | T7 |

A level counts as **demonstrated** after `evidenceMinSuccesses` (20) successes at that level within `evidenceWindowDays` (90).

Check against gating: each ceiling is at or above the `TRUST_THRESHOLDS_BY_RISK` value of the next level up (LOW 200 ≤ 499, MEDIUM 400 ≤ 649, HIGH 600 ≤ 799, CRITICAL 800 ≤ 950, LIFE_CRITICAL 951 ≤ 1000). Without that property an agent could never earn the right to attempt the level it needs to climb.

### 5.5 Volume normalisation

Within each `volumeWindowHours` (24) window, every event of a given risk level carries the weight:

```
w = min(1, fullWeightEventsPerLevel / n_level_window)     fullWeightEventsPerLevel = 50
```

That weight applies to gains **and** losses, so the break-even success rate is unchanged. Without it on the loss side, a high-volume agent at 99.5% success would lose ground every day.

**Settlement.** `n` is only known when the window closes, so:

- gains in the window are **provisional** and settle at window close with the final `w`;
- losses apply **immediately at w = 1** and are re-weighted at window close. The difference, `(1 − w) × loss`, is credited back.

Applying losses immediately at full weight stops an agent front-loading safe volume and then failing late in the window, when `w` would be lowest.

The risk accumulator is **not** normalised: each failure still adds `P(T) × R` at full value. Severity is per failure, not per unit of evidence.

### 5.6 Severe-failure demotion

A single failure whose accumulator contribution `P(T) × R` is at or above `severeFailureThreshold` (120, equal to `RISK_ACCUMULATOR.degradedThreshold`) demotes the agent **one tier immediately**, bypassing hysteresis.

| Tier | HIGH (R=10) | CRITICAL (R=15) | LIFE_CRITICAL (R=30) |
|---|---|---|---|
| T4 (P=7) | 70 | not permitted | not permitted |
| T5 (P=8) | 80 | **120: demote** | not permitted |
| T6 (P=9) | 90 | **135: demote** | not permitted |
| T7 (P=10) | 100 | **150: demote** | **300: demote, and the accumulator trips the circuit breaker** |

Together with the unchanged accumulator, this puts severe failures under an explicit, auditable rule instead of an emergent score drop.

### 5.7 Agent class prior, CAR binding and class change

- The agent class is assigned by the **certifier**, bound to the CAR ID, and recorded in the agent's manifest or registry entry. It MUST NOT be self-declared.
- The class sets one value: the default risk level for actions the enforcement point **cannot classify**.
- Unclassified actions **gain at READ** (ρ = 0) and **lose at the class default**. This deliberately breaks the ratio invariant for unclassified work, so that classifying actions is always the better choice for an operator.
- On any change of class or risk profile:
  - the score is capped at the top of the tier **below** the current one;
  - the set of demonstrated levels is reset;
  - the change is recorded as a proof event linked to the CAR ID.

---

## 6. Gaming analysis

| Attack | Today | With this RFC |
|---|---|---|
| Farm low-risk volume | Reaches T5 in 2 days (agent L) | Capped at 648.8 (T3) by the LOW ceiling; takes 23 days to reach it |
| Claim a faster class | Not applicable | Class is certifier-assigned and CAR-bound; a class change caps the score and resets demonstrated levels |
| Inflate ρ on own actions | Not applicable | ρ is assigned by the enforcement point and re-derivable from the proof event; step-up capped at one level |
| Seek risk for faster gain | Damped by ∛R | Gated by `TRUST_THRESHOLDS_BY_RISK`; at fixed tier and position the break-even is the same at every level, so higher risk pays only through demonstrated evidence |
| Park near the ceiling | Blocked by midpoint loss reference | Unchanged: loss still uses `ln(1 + C/2)` on the observation ceiling |
| Avoid classification | Not applicable | Unclassified work gains at READ and loses at the class default |
| Time failures late in the window | Not applicable | Losses apply at full weight immediately; only the refund is deferred |
| Split one agent into many | Not applicable | Out of scope here. Each CAR ID starts at `INITIAL_TRUST_SCORE`, and `TRUST_INHERITANCE` is NONE, so splitting buys no score; shared-key detection belongs in the registry |

---

## 7. Worked example

Agents L and H from §2, observation ceiling 1000, with k ∈ [0.05, 0.25], the evidence ceiling and normalisation at 50:

| Agent | T3 | T4 | T5 | Final score |
|---|---|---|---|---|
| L | day 23 | never | never | 648.8 (capped by LOW evidence) |
| H | day 262 | day 305 | day 341 | 949.2 (capped by HIGH evidence; T7 needs CRITICAL) |

Compared with today, L goes from T5 in 2 days to a hard stop at T3. H reaches T4 about 25 days sooner than today (day 305 against day 330).

With k ∈ [0.01, 0.05] and the same mechanisms, L still stops at T3 (on day 111), but H needs **1,523 days** to reach T4.

---

## 8. Not modelled

The figures come from a deterministic expected-value model (`rfcs/examples/0008-model.mjs`), not a Monte Carlo simulation. It ignores:

- hysteresis, promotion delays and dormancy;
- the risk accumulator's warning and degraded states;
- the variance of real success streams.

For agent L, the accumulator would see about 10 failures a day. At T3 that comes to roughly 84 per 24 hours, above the warning threshold (60) and below the degraded threshold (120). The model does not apply that state, so a busy agent's practical ceiling may be lower than shown.

---

## 9. `canonical.ts` shape

This draft adds a single non-normative export and changes no existing value or function:

```ts
/** @experimental RFC-0008 draft. Not used by any formula in this file. */
export const PROPOSED_RFC_0008 = {
  status: 'draft',
  gainRateMin: 0.05,
  gainRateMax: 0.25,
  riskFactors: { READ: 0, LOW: 0.15, MEDIUM: 0.35, HIGH: 0.6, CRITICAL: 0.85, LIFE_CRITICAL: 1 },
  maxRiskFactorStepUp: 1,
  evidenceCeilings: { READ: 499, LOW: 649, MEDIUM: 799, HIGH: 950, CRITICAL: 1000, LIFE_CRITICAL: 1000 },
  evidenceMinSuccesses: 20,
  evidenceWindowDays: 90,
  volumeWindowHours: 24,
  fullWeightEventsPerLevel: 50,
  severeFailureThreshold: 120,
} as const;
```

On acceptance, the values move to top-level constants (`GAIN_RATE_MIN`, `GAIN_RATE_MAX`, `RISK_FACTORS`, `EVIDENCE_CEILINGS`, `VOLUME_NORMALIZATION`, `SEVERE_FAILURE_THRESHOLD`), and `calculateGain` and `calculateLoss` change signature to take the risk level, `C_eff` and `w`. `GAIN_RATE` stays exported and deprecated, equal to `GAIN_RATE_MIN`, for one minor version.

---

## 10. Conformance and migration

- **Major spec version.** Gain and loss values change for every level above READ, so acceptance requires `BASIS_SPEC_VERSION` 2.0.0.
- **Golden vectors.** `trust-formulas.test.ts` asserts `GAIN_RATE × ln(1 + C) × ∛R`. Acceptance replaces that with known-answer vectors for every risk level, and adds vectors for:
  - the evidence ceiling;
  - window settlement, including the late-failure case;
  - severe-failure demotion at each row of §5.6.
- **Existing scores.** Scores are not recomputed. On migration, each agent's demonstrated levels are seeded from its last 90 days of proof events, and the score is capped at its new `C_eff`.
- **Downstream.** `basis-scorer`, the `apps/rainbow` simulator, `cognigate-api` and `@vorionsys/contracts` all implement or document today's formulas, and each needs a matching change.

---

## 11. Alternatives considered

- **k ∈ [0.01, 0.05].** This is the range first discussed, and it also lines up with the contracts `gainRate` default of 0.01. It slows all agents 2.5x to 5x relative to today's spec (agent H takes 1,523 days to reach T4) and does nothing about volume on its own. Kept as a recorded option; not chosen.
- **Keep loss proportional to R (severity) and change only gain.** This preserves today's failure costs, but the ratio then drifts by `R/k(a)` and break-even varies with the risk mix. That is the drift this RFC set out to remove.
- **Gain by agent type instead of by action.** Whoever picks the type controls the climb speed. Agents drift across types, and a fixed type list ages badly. Rejected; type survives only as the prior for unclassified actions (§5.7).

---

## 12. Open questions

1. ~~Rate bounds~~: **resolved 2026-11-21, [0.05, 0.25].** [0.01, 0.05] stays recorded under §11.
2. Is severe-failure demotion at `P(T) × R ≥ 120` the right threshold, or should any CRITICAL failure demote regardless of tier?
3. Should `evidenceMinSuccesses` scale with level (for example, fewer required at CRITICAL, where volume is naturally low)?
4. Should volume normalisation be per level (as drafted) or across all levels combined?
5. Does the evidence ceiling belong in BASIS, or in the certification profile layered on top of it?
