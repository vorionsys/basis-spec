// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * RFC-8785 JCS — JSON Canonicalization Scheme.
 *
 * This is the ONE canonical serializer for this package. It deliberately does
 * NOT "mirror" the repo's proof-chain canonicalizer (packages/basis-scorer
 * policy-hash.ts / rfcs/0002 §"Canonical serialization"), which sorts object
 * keys in ASCII-BYTE order. RFC-8785 mandates sorting by UTF-16 CODE UNIT.
 *
 * For pure-ASCII keys the two orderings PROVABLY COINCIDE, and every key in
 * this package's genesis + leaf records is ASCII (see ASCII_KEY_INVARIANT and
 * its test). We therefore pick the stricter, internationally specified
 * RFC-8785 rule as the single source of truth so a future non-ASCII field can
 * never silently diverge between this lib and a fresh RFC-8785 implementation.
 *
 * Determinism guarantees:
 *  - object keys sorted by UTF-16 code unit (RFC-8785 §3.2.3);
 *  - numbers serialized via ECMAScript Number::toString (RFC-8785 §3.2.2.3,
 *    which is exactly what JSON.stringify emits for finite doubles);
 *  - NaN / Infinity / -Infinity rejected (not representable);
 *  - undefined / function / symbol / bigint rejected;
 *  - cycles rejected;
 *  - -0 normalized to 0 (RFC-8785 requires the value 0, not "-0");
 *  - strings escaped with JSON.stringify's minimal, lowercase-\u escaping,
 *    which is RFC-8785-compatible for the quoting step.
 *
 * This module contains ZERO floating-point arithmetic of its own (it only
 * delegates number *formatting* to the engine) and NO Date.now / Math.random.
 */

/**
 * Documented invariant: all object keys passed to {@link jcsCanonicalize} for
 * a CAR genesis or a transparency-log leaf are ASCII. Under this invariant the
 * RFC-8785 UTF-16-code-unit key sort and the repo's ASCII-byte key sort yield
 * the identical ordering, so a relying party using either discipline computes
 * the same bytes. Non-ASCII keys are still canonicalized correctly here (by
 * the RFC-8785 rule); the invariant is about cross-impl agreement, not safety.
 */
export const ASCII_KEY_INVARIANT =
  'genesis + leaf object keys are ASCII (RFC-8785 and ASCII-byte sort agree)';

function quoteString(s: string): string {
  // JSON.stringify performs RFC-8785-compatible minimal escaping (lowercase
  // \u for control chars, escapes only " \ and C0 controls). Asserted by the
  // RFC-8785 reference vectors + a control-char vector in the test suite.
  return JSON.stringify(s);
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new RangeError('jcs: non-finite number is not representable');
  }
  // Normalize -0 to 0 (RFC-8785 §3.2.2.3 — the value is 0).
  if (Object.is(n, -0)) return '0';
  // ECMAScript Number::toString === what JSON.stringify emits for a finite
  // double (e.g. 1e+21, 1e-7, 5e-324). RFC-8785 §3.2.2.3 defers to exactly
  // this algorithm.
  return JSON.stringify(n);
}

function canon(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';

  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'string') return quoteString(value as string);
  if (t === 'number') return serializeNumber(value as number);

  if (t === 'bigint') {
    throw new TypeError('jcs: bigint is not representable in canonical JSON');
  }
  if (t === 'undefined' || t === 'function' || t === 'symbol') {
    throw new TypeError(`jcs: value of type ${t} is not representable`);
  }

  // object or array
  const obj = value as object;
  if (seen.has(obj)) {
    throw new TypeError('jcs: cyclic structure cannot be canonicalized');
  }
  seen.add(obj);
  try {
    if (Array.isArray(value)) {
      // Arrays preserve order. An undefined / function / symbol element is not
      // representable (JSON would coerce to null, which would silently change
      // meaning) — reject it instead of coercing.
      const parts = value.map((el) => canon(el, seen));
      return `[${parts.join(',')}]`;
    }

    const record = value as Record<string, unknown>;
    // RFC-8785 §3.2.3: sort property names by UTF-16 code unit. JavaScript's
    // default Array.prototype.sort on strings compares by UTF-16 code unit,
    // which is exactly the RFC-8785 rule.
    const keys = Object.keys(record).sort();
    const members: string[] = [];
    for (const k of keys) {
      const v = record[k];
      // RFC-8785: properties whose value is undefined are omitted (matching
      // JSON.stringify). functions/symbols are likewise dropped by JSON; we
      // drop only undefined here and let canon() reject function/symbol values
      // if they are *array* elements (where dropping would shift indices).
      if (v === undefined) continue;
      if (typeof v === 'function' || typeof v === 'symbol') continue;
      members.push(`${quoteString(k)}:${canon(v, seen)}`);
    }
    return `{${members.join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}

/**
 * Canonicalize a JSON value per RFC-8785 (JCS).
 *
 * THROWS on a non-canonicalizable value (NaN, Infinity, undefined top-level,
 * bigint, function/symbol as an array element, cycle). Callers that must be
 * fail-closed (every verify*) wrap this in try/catch and convert the throw to
 * {valid:false,reason:'noncanonical_*'} — JCS itself throws so the bug is
 * never silently swallowed by producing wrong bytes.
 */
export function jcsCanonicalize(value: unknown): string {
  return canon(value, new Set<object>());
}

/** UTF-8 bytes of the canonical serialization — the exact pre-image to hash. */
export function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcsCanonicalize(value));
}
