// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { createHash } from 'node:crypto';

/**
 * Deterministic canonical-JSON + SHA-256 of the scoring policy.
 *
 * MUST-FIX (reviewer #3): risk is NOT carried in the signed proof chain —
 * `execution_completed` / `execution_failed` carry no RiskLevel. Risk is
 * resolved only by walking the linkage to `intent_received.actionType` and
 * then mapping that free-form string through the CALLER-SUPPLIED
 * `policy.riskByActionType`. The same party that asserts the tier therefore
 * controls the risk multiplier (hence gain/loss magnitude) and the
 * observation cap (`assertVerifiedObservation`).
 *
 * The scorer cannot detect a mislabelled policy because the truth simply is
 * not in the chain. What it CAN and MUST do is make the recomputation
 * reproducible and attributable: we hash the exact policy used into the
 * result (`policyHash`). Two parties scoring the same chain with the same
 * policy get the same `policyHash`; a different policy is visibly a
 * different input. The README states plainly that risk integrity depends on
 * policy integrity, which is out of the signed chain (RFC-0002.1 limitation).
 *
 * Canonical JSON rules mirror RFC-0002 §"Canonical serialization": object
 * keys sorted ASCII-byte order, no whitespace, `undefined` keys omitted.
 */
function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RangeError('non-finite number cannot be canonicalised');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const body = keys
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
      .join(',');
    return `{${body}}`;
  }
  // functions, symbols, bigint, undefined — not part of a serialisable policy
  throw new TypeError(`unserialisable policy value of type ${typeof value}`);
}

/** SHA-256 (hex, lowercase) of the canonical-JSON serialisation of the policy. */
export function hashPolicy(policy: unknown): string {
  const json = canonicalJson(policy);
  return createHash('sha256').update(json, 'utf8').digest('hex');
}
