// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Suite metadata — embedded in every conformance results document so
 * verifiers know exactly what version of the suite produced them.
 *
 * SUITE_REVISION is a placeholder string at build time. The publish
 * pipeline replaces it with the git sha of the source the build was
 * cut from. Verifiers compare this to a known-good revision when
 * deciding whether to trust an attestation that cites this suite.
 */

export const SUITE_NAME = '@vorionsys/basis-conformance' as const;
export const SUITE_VERSION = '0.1.0' as const;
export const SUITE_REVISION =
  process.env.BASIS_CONFORMANCE_REVISION ?? 'dev-build';
export const SUITE_SOURCE = 'https://github.com/vorionsys/basis-spec' as const;
