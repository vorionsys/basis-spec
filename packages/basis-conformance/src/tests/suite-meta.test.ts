// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Suite-metadata guards.
 *
 * SUITE_VERSION is embedded in every conformance results document, and
 * verifiers are told to compare it against a known-good release when
 * deciding whether to trust an attestation. That makes a stale value worse
 * than a missing one: it is a confident, wrong provenance claim.
 *
 * It cannot be read from package.json at runtime (it must survive bundling
 * as a compile-time constant), so the only thing keeping it honest is this
 * test. It exists because the two DID drift — suite-meta said 0.1.1 while
 * the published package was 0.2.0 — and nothing caught it.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SUITE_NAME, SUITE_VERSION } from '../suite-meta.js';

const PKG = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'),
    'utf-8',
  ),
) as { name: string; version: string };

describe('suite metadata', () => {
  it('SUITE_VERSION matches the package version exactly', () => {
    expect(SUITE_VERSION).toBe(PKG.version);
  });

  it('SUITE_NAME matches the package name exactly', () => {
    expect(SUITE_NAME).toBe(PKG.name);
  });

  it('SUITE_VERSION is a plain semver triple, not a range or tag', () => {
    expect(SUITE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
