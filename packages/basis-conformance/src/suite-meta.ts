// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Suite metadata — embedded in every conformance results document so
 * verifiers know exactly what version of the suite produced them.
 *
 * SUITE_REVISION resolution order:
 *   1. `revision.json` next to this compiled module (written into dist/
 *      by `scripts/prepare-dist.mjs` during `npm run build` with the git
 *      sha the build was cut from — GITHUB_SHA in CI, `git rev-parse
 *      HEAD` locally);
 *   2. the BASIS_CONFORMANCE_REVISION environment variable;
 *   3. the literal 'dev-build' — unstamped local development only.
 *
 * Verifiers compare this to a known-good revision when deciding whether
 * to trust an attestation that cites this suite.
 */

import { readFileSync } from 'node:fs';

export const SUITE_NAME = '@vorionsys/basis-spec-conformance' as const;
export const SUITE_VERSION = '0.1.1' as const;

function readStampedRevision(): string | undefined {
  try {
    const raw = readFileSync(
      new URL('./revision.json', import.meta.url),
      'utf-8',
    );
    const parsed = JSON.parse(raw) as { revision?: unknown };
    return typeof parsed.revision === 'string' && parsed.revision.length > 0
      ? parsed.revision
      : undefined;
  } catch {
    return undefined;
  }
}

export const SUITE_REVISION =
  readStampedRevision() ??
  process.env.BASIS_CONFORMANCE_REVISION ??
  'dev-build';
export const SUITE_SOURCE = 'https://github.com/vorionsys/basis-spec' as const;
