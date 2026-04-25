// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * @basis-spec/basis-conformance — public entry.
 *
 * v0.1 ships in self-test mode: the suite runs against the canonical
 * TypeScript representation of the spec (`@basis-spec/basis`) and the
 * RFC schemas in this repo. A passing run proves the spec is internally
 * coherent and that the canonical impl correctly implements it.
 *
 * v0.2 will add vendor-endpoint mode: point the suite at a live BASIS-
 * compliant runtime URL and verify that runtime's behavior matches the
 * spec end-to-end. Spec for the endpoints required is forthcoming as
 * RFC-0004.
 *
 * Usage from code:
 *   import { runConformance } from '@basis-spec/basis-conformance/runner';
 *   const results = await runConformance();
 *   // results: { passed, failed, skipped, total, details, suite: {...} }
 *
 * Usage from CLI:
 *   npx basis-conformance run [--out results.json] [--reporter text|json]
 */

export { runConformance, type ConformanceResults } from './runner.js';
export {
  SUITE_NAME,
  SUITE_VERSION,
  SUITE_REVISION,
  SUITE_SOURCE,
} from './suite-meta.js';
