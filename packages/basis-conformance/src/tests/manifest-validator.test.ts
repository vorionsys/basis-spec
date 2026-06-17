// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Truth-only manifest validator tests — RFC-0002 §"Schema".
 *
 * These load EXTERNAL manifest fixtures from disk (JSON files that could
 * have come from any runtime) and assert the validator reports structural
 * facts only — no trust/compliance verdict, no signature/hash verification.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateManifest } from '../manifest-validator.js';

const here = dirname(fileURLToPath(import.meta.url));
const loadFixture = (name: string): unknown =>
  JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf-8'));

describe('manifest-validator: VALID external manifest', () => {
  it('a well-formed two-event manifest validates with no errors', () => {
    const manifest = loadFixture('manifest-valid.json');
    const r = validateManifest(manifest);
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
  });
});

describe('manifest-validator: INVALID external manifest', () => {
  it('a malformed event surfaces structural errors with index + field', () => {
    const manifest = loadFixture('manifest-invalid.json');
    const r = validateManifest(manifest);
    expect(r.valid).toBe(false);
    expect(r.errors.length).toBeGreaterThan(0);
    // every error points at event index 0
    expect(r.errors.every((e) => e.index === 0)).toBe(true);
    const fields = r.errors.map((e) => e.field);
    expect(fields).toContain('eventId'); // missing
    expect(fields).toContain('eventHash'); // 'tooshort'
    expect(fields).toContain('previousHash'); // 'NOT-HEX'
    expect(fields).toContain('occurredAt'); // space, not ISO-8601 'T'
    expect(fields).toContain('verificationId'); // shadowMode=rejected requires it
    expect(fields).toContain('verifiedAt'); // shadowMode=rejected requires it
  });
});

describe('manifest-validator: top-level shape', () => {
  it('a non-array manifest is rejected at index -1', () => {
    const r = validateManifest({ not: 'an array' });
    expect(r.valid).toBe(false);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0].index).toBe(-1);
    expect(r.errors[0].field).toBe('(manifest)');
  });

  it('an empty manifest is trivially valid (structure only)', () => {
    const r = validateManifest([]);
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
  });

  it('does NOT reject events for an absent signature (signatures are not its job)', () => {
    const manifest = loadFixture('manifest-valid.json') as Array<
      Record<string, unknown>
    >;
    // none of the events carry `signature`/`signedBy`; still valid.
    const r = validateManifest(manifest);
    expect(r.valid).toBe(true);
  });
});
