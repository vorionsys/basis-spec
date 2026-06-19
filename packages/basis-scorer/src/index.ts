// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * @vorionsys/basis-scorer — entry point.
 *
 * The BASIS reference scorer: deterministic `evidence → score → tier` with the
 * fail-closed `effectiveTier = min(claimed, recomputed, observation ceiling,
 * policy ceiling)`, the frozen CAR-5 ⇄ T0–T7 projection, and golden vectors.
 * Built on @vorionsys/basis-spec canonical constants.
 */

export * from './reconciliation.js';
export * from './scorer.js';
export * from './golden-vectors.js';
