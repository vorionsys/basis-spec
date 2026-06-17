// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

import { describe, it, expect } from 'vitest';
import { jcsCanonicalize, jcsBytes } from '../jcs.js';

describe('JCS — RFC-8785 reference vectors', () => {
  it('sorts object keys by UTF-16 code unit, no whitespace', () => {
    // RFC-8785 §3.2.3 style example.
    const input = { b: 1, a: 2, c: { y: 3, x: 4 } };
    expect(jcsCanonicalize(input)).toBe('{"a":2,"b":1,"c":{"x":4,"y":3}}');
  });

  it('serializes numbers per ECMAScript Number::toString', () => {
    // The classic RFC-8785 number edge cases.
    expect(jcsCanonicalize(1e21)).toBe('1e+21');
    expect(jcsCanonicalize(1e-7)).toBe('1e-7');
    expect(jcsCanonicalize(0)).toBe('0');
    expect(jcsCanonicalize(-1.5)).toBe('-1.5');
    expect(jcsCanonicalize(333333333.3333333)).toBe('333333333.3333333');
  });

  it('normalizes -0 to 0', () => {
    expect(jcsCanonicalize(-0)).toBe('0');
    expect(jcsCanonicalize({ a: -0 })).toBe('{"a":0}');
  });

  it('escapes control characters with lowercase \\u (RFC-8785 string vector)', () => {
    // Tab, newline, and a control char.
    expect(jcsCanonicalize('\t')).toBe('"\\t"');
    expect(jcsCanonicalize('\n')).toBe('"\\n"');
    expect(jcsCanonicalize('')).toBe('"\\u0001"');
    expect(jcsCanonicalize('a"\\b')).toBe('"a\\"\\\\b"');
  });

  it('arrays preserve order', () => {
    expect(jcsCanonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('jcsBytes returns the UTF-8 bytes of the canonical string', () => {
    const bytes = jcsBytes({ a: 1 });
    expect(Buffer.from(bytes).toString('utf8')).toBe('{"a":1}');
  });
});

describe('JCS — fail-closed on non-canonicalizable values (THROWS)', () => {
  it('rejects NaN', () => {
    expect(() => jcsCanonicalize(NaN)).toThrow();
    expect(() => jcsCanonicalize({ a: NaN })).toThrow();
  });
  it('rejects Infinity / -Infinity', () => {
    expect(() => jcsCanonicalize(Infinity)).toThrow();
    expect(() => jcsCanonicalize(-Infinity)).toThrow();
  });
  it('rejects bigint', () => {
    expect(() => jcsCanonicalize(10n)).toThrow();
  });
  it('rejects a function / symbol as an ARRAY element (no silent null coercion)', () => {
    expect(() => jcsCanonicalize([() => 1])).toThrow();
    expect(() => jcsCanonicalize([Symbol('x')])).toThrow();
  });
  it('rejects a cyclic structure', () => {
    const a: Record<string, unknown> = {};
    a['self'] = a;
    expect(() => jcsCanonicalize(a)).toThrow();
  });
  it('omits an undefined object property (matching JSON), keeps others', () => {
    expect(jcsCanonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });
  it('rejects a top-level undefined', () => {
    expect(() => jcsCanonicalize(undefined)).toThrow();
  });
});
