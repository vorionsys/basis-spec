// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Known-answer canonicalization vectors — RFC 8785 divergence axes.
 *
 * Naming a property is not pinning it. This canonicalizer was already correct
 * on every axis below, but correct because JavaScript's default comparator
 * happens to match RFC 8785 §3.2.3, not because anything held it there.
 * Swapping in `localeCompare` passed the entire suite while changing the bytes,
 * because no vector contained a single non-ASCII key.
 *
 * So these tests assert the PROPERTY, not only that output equals a recorded
 * string. A pure string-equality test is laundered the moment someone
 * regenerates the file after a regression: the recorded value moves with the
 * bug and the suite goes green. Asserting "the surrogate key sorts first"
 * survives regeneration, because it restates the spec rather than the output.
 *
 * Spec: RFC 8785 §3.1 (no normalization), §3.2.2 (minimal escaping),
 *       §3.2.3 (sort by UTF-16 code units)
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../chain-verifier.js';

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vectors');

interface KnownAnswer {
  id: string;
  axis: string;
  why: string;
  input: Record<string, unknown>;
  expectedKeyOrder: string[];
  canonical: string;
  canonicalUtf8Hex: string;
  sha256: string;
}

const file = JSON.parse(
  readFileSync(join(VECTORS, 'canonical-known-answers.json'), 'utf-8'),
) as { cases: KnownAnswer[] };

/** Position of a key's opening quote in the canonical output. */
const keyPos = (canonical: string, key: string): number => canonical.indexOf(JSON.stringify(key));

describe('known-answer canonicalization vectors', () => {
  it('covers every axis where a JCS implementation silently diverges', () => {
    // Deleting a case must fail, not quietly shrink the contract.
    const ids = file.cases.map((c) => c.id).sort();
    expect(ids).toEqual(
      [
        'locale-independent-ordering',
        'no-unicode-normalization',
        'non-ascii-emitted-raw',
        'utf16-code-unit-ordering',
      ].sort(),
    );
  });

  for (const c of file.cases) {
    describe(`${c.id} — ${c.axis}`, () => {
      it('reproduces the pinned bytes exactly', () => {
        const actual = canonicalize(c.input);
        expect(actual).toBe(c.canonical);
        const bytes = Buffer.from(actual, 'utf8');
        expect(bytes.toString('hex')).toBe(c.canonicalUtf8Hex);
        expect(createHash('sha256').update(bytes).digest('hex')).toBe(c.sha256);
      });

      it('emits keys in the declared order', () => {
        const actual = canonicalize(c.input);
        const positions = c.expectedKeyOrder.map((k) => keyPos(actual, k));
        expect(positions.every((p) => p >= 0)).toBe(true);
        // Strictly increasing = the declared order is the emitted order.
        for (let i = 1; i < positions.length; i++) {
          expect(positions[i]!).toBeGreaterThan(positions[i - 1]!);
        }
      });
    });
  }
});

/**
 * The property assertions. These restate RFC 8785 rather than the output, so
 * they still fail if someone regenerates the vector file on top of a bug.
 */
describe('RFC 8785 properties, asserted independently of the recorded bytes', () => {
  it('§3.2.3 sorts by UTF-16 code units, not code points', () => {
    // U+10000 encodes as D800 DC00. Its first code unit is below 0xFFFD, so it
    // sorts FIRST despite the higher code point. Code-point ordering reverses
    // this, and every downstream hash changes.
    const out = canonicalize({ '�': 1, '\u{10000}': 2 });
    expect(keyPos(out, '\u{10000}')).toBeLessThan(keyPos(out, '�'));
  });

  it('§3.2.3 ordering is not locale-aware', () => {
    // localeCompare puts "ä" beside "a". Code units put it after "z".
    const out = canonicalize({ z: 1, 'ä': 2, a: 3 });
    expect(keyPos(out, 'ä')).toBeGreaterThan(keyPos(out, 'z'));
  });

  it('§3.1 does not normalize, so composed and decomposed stay distinct', () => {
    const out = canonicalize({ 'é': 'composed', 'é': 'decomposed' });
    // Two keys in, two keys out. An NFC-normalizing canonicalizer silently
    // collapses these and drops a field.
    expect(Object.keys(JSON.parse(out))).toHaveLength(2);
  });

  it('§3.2.2 emits non-ASCII raw rather than \\uXXXX escaped', () => {
    const out = canonicalize({ k: 'é\u{1F600}' });
    expect(out).toContain('é');
    expect(out).not.toContain('\\u00e9');
  });
});
