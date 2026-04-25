// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Canonical-JSON serialization tests — RFC-0002 §"Canonical
 * serialization". The hash chain breaks if any two impls disagree on
 * how to serialize a payload to bytes before sha256ing it.
 *
 * v0.1 ships a reference canonicalizer and tests its properties. v0.2
 * will export the canonicalizer publicly so vendor impls can use the
 * exact same bytes to verify cross-impl equality.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md §"Canonical
 * serialization"
 */

import { describe, it, expect } from 'vitest';

/**
 * Reference canonicalizer per RFC-0002:
 *   - keys sorted ASCII-byte order
 *   - no whitespace
 *   - shortest decimal numbers (Number.toString default)
 *   - null preserved, undefined keys omitted
 */
function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical JSON requires finite numbers');
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const v = value as Record<string, unknown>;
    const keys = Object.keys(v)
      .filter((k) => v[k] !== undefined)
      .sort();
    const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonical JSON does not support type ${typeof value}`);
}

describe('canonical-json: key ordering', () => {
  it('object keys are sorted ASCII order', () => {
    const out = canonicalize({ z: 1, a: 2, m: 3 });
    expect(out).toBe('{"a":2,"m":3,"z":1}');
  });

  it('nested objects sort their keys too', () => {
    const out = canonicalize({ outer: { z: 1, a: 2 } });
    expect(out).toBe('{"outer":{"a":2,"z":1}}');
  });

  it('two structurally-equal objects with different key order produce identical bytes', () => {
    const a = canonicalize({ x: 1, y: 2 });
    const b = canonicalize({ y: 2, x: 1 });
    expect(a).toBe(b);
  });
});

describe('canonical-json: whitespace', () => {
  it('no whitespace in output', () => {
    const out = canonicalize({ a: 1, b: [1, 2, 3], c: 'x' });
    expect(out).not.toMatch(/\s/);
  });
});

describe('canonical-json: numbers', () => {
  it('integers serialize without trailing zero', () => {
    expect(canonicalize(42)).toBe('42');
  });

  it('decimals serialize as shortest form', () => {
    expect(canonicalize(0.5)).toBe('0.5');
  });

  it('negative numbers preserve sign', () => {
    expect(canonicalize(-3.14)).toBe('-3.14');
  });

  it('Infinity throws (finite-only constraint)', () => {
    expect(() => canonicalize(Infinity)).toThrow();
  });

  it('NaN throws (finite-only constraint)', () => {
    expect(() => canonicalize(NaN)).toThrow();
  });
});

describe('canonical-json: null and undefined', () => {
  it('null is preserved', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize({ a: null })).toBe('{"a":null}');
  });

  it('undefined keys are omitted', () => {
    expect(canonicalize({ a: 1, b: undefined, c: 2 })).toBe('{"a":1,"c":2}');
  });
});

describe('canonical-json: idempotence', () => {
  it('canonicalizing twice yields the same string', () => {
    const obj = { a: { x: 1, y: 2 }, b: [3, 1, 2] };
    const once = canonicalize(obj);
    const twice = canonicalize(JSON.parse(once));
    expect(twice).toBe(once);
  });
});
