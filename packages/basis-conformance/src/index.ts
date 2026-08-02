// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * @vorionsys/basis-spec-conformance — public entry.
 *
 * v0.1 ships in self-test mode: the suite runs against the canonical
 * TypeScript representation of the spec (`@vorionsys/basis-spec`) and the
 * RFC schemas in this repo. A passing run proves the spec is internally
 * coherent and that the canonical impl correctly implements it.
 *
 * v0.2 will add vendor-endpoint mode: point the suite at a live BASIS-
 * compliant runtime URL and verify that runtime's behavior matches the
 * spec end-to-end. Spec for the endpoints required is forthcoming as
 * RFC-0004.
 *
 * Usage from code:
 *   import { runConformance } from '@vorionsys/basis-spec-conformance/runner';
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

/**
 * Truth-only structural validator for an external proof-chain manifest.
 * Checks RFC-0002 required-field presence/shape only — emits no trust or
 * compliance verdict and does not verify signatures or hash linkage.
 */
export {
  validateManifest,
  type ManifestError,
  type ManifestValidationResult,
} from './manifest-validator.js';

/**
 * Public reference verifier for RFC-0002 §"Verification procedure".
 *
 * Where `validateManifest` is truth-only and structural, this actually
 * recomputes the canonical-JSON bytes, re-derives `eventHash` (sha256) and
 * `eventHash3` (sha3-256), walks `previousHash` linkage, and verifies
 * detached Ed25519 signatures. It answers "is this record intact and did
 * the claimed signer produce it" — and nothing beyond that. A chain that
 * verifies is a chain that has not been altered; it is not a statement
 * that the agent behaved well.
 */
export {
  verifyChain,
  canonicalize,
  canonicalEventString,
  canonicalEventBytes,
  toEd25519PublicKey,
  type ChainVerificationReport,
  type EventVerification,
  type VerifyChainOptions,
  type SignatureDomain,
} from './chain-verifier.js';
