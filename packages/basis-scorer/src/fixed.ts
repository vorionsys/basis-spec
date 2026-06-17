// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Deterministic fixed-point arithmetic for the scorer.
 *
 * The only unavoidable floating-point operations in BASIS scoring are
 * `Math.log` and `Math.cbrt` inside the canonical `calculateGain` /
 * `calculateLoss`. ECMAScript does NOT guarantee these are bit-identical
 * across libm implementations, so a naive float accumulator could diverge
 * in the last ULP across platforms.
 *
 * Determinism strategy (per the ratified design + reviewer must-fix #5):
 *
 *   1. The running score is held as a SCALED INTEGER (BigInt) at a pinned
 *      `precision` scale (default 1e6). The accumulator is therefore exact —
 *      no float drift accumulates across thousands of steps.
 *   2. Each canonical gain/loss result is immediately quantized with
 *      round-half-even at the pinned scale BEFORE being added.
 *   3. CRITICAL (must-fix #5): `calculateGain` depends on the *current*
 *      score (headroom = ceiling − currentScore), so the value fed back into
 *      the next `Math.log` must itself be the quantized score, not a raw
 *      float running sum. We always reconstruct the float `currentScore`
 *      from the scaled integer via a single pinned division
 *      (`Number(scaled) / scale`) so the input to `ln` is identical on every
 *      platform. The float→int round-half-even on the *output* then absorbs
 *      any residual libm ULP difference.
 *
 * Round-half-even (banker's rounding) is chosen because it is symmetric and
 * has no positive bias, and it is what IEEE-754 uses by default — keeping
 * the quantization itself well-defined.
 */

export const DEFAULT_PRECISION = 1_000_000;

/**
 * Round-half-even of `x * scale` to the nearest integer, returned as a
 * BigInt. Deterministic for any finite `x`; throws for non-finite input so
 * the caller fails closed rather than producing NaN/Infinity scores.
 */
export function quantize(x: number, scale: number): bigint {
  if (!Number.isFinite(x)) {
    throw new RangeError(`non-finite value cannot be quantized: ${x}`);
  }
  const scaled = x * scale;
  // floor toward -Infinity so the fractional part is always in [0, 1).
  const floor = Math.floor(scaled);
  const frac = scaled - floor;
  let n: number;
  if (frac < 0.5) {
    n = floor;
  } else if (frac > 0.5) {
    n = floor + 1;
  } else {
    // exactly .5 — round to even
    n = floor % 2 === 0 ? floor : floor + 1;
  }
  return BigInt(n);
}

/** Reconstruct the float value from a scaled BigInt via one pinned division. */
export function unscale(scaled: bigint, scale: number): number {
  return Number(scaled) / scale;
}

/** Clamp a scaled-integer score into the scaled `[min, max]` range. */
export function clampScaled(scaled: bigint, minScaled: bigint, maxScaled: bigint): bigint {
  if (scaled < minScaled) return minScaled;
  if (scaled > maxScaled) return maxScaled;
  return scaled;
}
