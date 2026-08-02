// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Compaction and disclosure — RFC-0007.
 *
 * COMPACTION IS APPEND-ONLY. It attests to a range that already exists; it
 * never removes, rewrites, or re-links anything. That is not a policy choice —
 * `previousHash` is inside the RFC-0002 canonical hash input, so re-pointing an
 * event changes its own `eventHash` and invalidates everything after it. The
 * chain cannot be edited, and that is the whole tamper-evidence guarantee.
 *
 * The cost is stated rather than hidden: compaction trades FULL-CHAIN
 * VERIFICATION for ROOT-ATTESTED MEMBERSHIP. Discard the events and `full`
 * verification is gone permanently — for you as well as for everyone else.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalEventBytes } from '@vorionsys/basis-spec';
import { auditPath } from './proof.js';
import { verifyPath } from './proof.js';
import { leafHash, merkleRoot, MerkleError } from './tree.js';
import type {
  ChainCompactedPayload,
  ChainEvent,
  DisclosurePackage,
  DisclosureVerification,
  DisclosureIssue,
} from './types.js';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function toPublicKey(key: string): ReturnType<typeof createPublicKey> {
  const t = key.trim();
  if (t.includes('BEGIN PUBLIC KEY')) return createPublicKey(t);
  const raw = /^[0-9a-f]{64}$/i.test(t)
    ? Buffer.from(t, 'hex')
    : Buffer.from(t, 'base64');
  if (raw.length !== 32) throw new Error(`Ed25519 key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

const hashable = (e: ChainEvent) => ({
  previousHash: e.previousHash,
  eventType: e.eventType,
  agentId: e.agentId,
  occurredAt: e.occurredAt,
  payload: e.payload,
});

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

export interface CompactOptions {
  readonly compactionId: string;
  /** Contiguous range in CHAIN ORDER. */
  readonly range: ReadonlyArray<ChainEvent>;
  /** Per-leaf salts, hex, aligned to `range`. Optional and default-off. */
  readonly salts?: ReadonlyArray<string | undefined>;
  readonly archiveUri?: string;
  readonly compactedAt: string;
}

/**
 * Build the `chain_compacted` payload for a range.
 *
 * Does NOT sign — signing belongs to whoever holds the key. The returned
 * payload must be sealed into an RFC-0002 event and signed; an unsigned
 * compaction is not a compaction, only an unattributed assertion that some
 * range had some root.
 */
export function buildCompaction(opts: CompactOptions): ChainCompactedPayload {
  const { range, salts } = opts;
  if (range.length === 0) {
    throw new MerkleError(
      'cannot compact a zero-length range — an empty compaction attests nothing and is indistinguishable from a suppressed range',
    );
  }
  if (salts && salts.length !== range.length) {
    throw new MerkleError(
      `salts length (${salts.length}) does not match range length (${range.length})`,
    );
  }

  // Contiguity: this must be a real chain segment, not an arbitrary selection.
  // Compacting a non-contiguous set would attest to a range that never existed.
  for (let i = 1; i < range.length; i++) {
    if (range[i]!.previousHash !== range[i - 1]!.eventHash) {
      throw new MerkleError(
        `range is not contiguous at index ${i}: previousHash does not match the prior event's eventHash`,
      );
    }
  }

  const leaves = range.map((e, i) => leafHash(hashable(e), salts?.[i]));

  return {
    type: 'chain_compacted',
    compactionId: opts.compactionId,
    merkleRoot: merkleRoot(leaves),
    firstEventId: range[0]!.eventId,
    lastEventId: range[range.length - 1]!.eventId,
    leafCount: range.length,
    rangePreviousHash: range[0]!.previousHash,
    rangeEventHash: range[range.length - 1]!.eventHash,
    ...(opts.archiveUri ? { archiveUri: opts.archiveUri } : {}),
    salted: Boolean(salts?.some((s) => s !== undefined)),
    compactedAt: opts.compactedAt,
  };
}

export interface BuildDisclosureOptions {
  /** The signed `chain_compacted` event. */
  readonly compaction: ChainEvent;
  /** The full range the compaction covers, in chain order. */
  readonly range: ReadonlyArray<ChainEvent>;
  readonly salts?: ReadonlyArray<string | undefined>;
  /** eventIds to reveal. */
  readonly disclose: ReadonlyArray<string>;
  /** signedBy → public key, for the compaction signature. */
  readonly keys: Readonly<Record<string, string>>;
}

/** Assemble a self-contained disclosure package. */
export function buildDisclosure(opts: BuildDisclosureOptions): DisclosurePackage {
  const leaves = opts.range.map((e, i) => leafHash(hashable(e), opts.salts?.[i]));
  const wanted = new Set(opts.disclose);

  const disclosed = opts.range
    .map((event, leafIndex) => ({ event, leafIndex }))
    .filter(({ event }) => wanted.has(event.eventId))
    .map(({ event, leafIndex }) => ({
      event,
      leafIndex,
      ...(opts.salts?.[leafIndex] ? { salt: opts.salts[leafIndex]! } : {}),
      path: auditPath(leaves, leafIndex),
    }));

  const missing = opts.disclose.filter(
    (id) => !disclosed.some((d) => d.event.eventId === id),
  );
  if (missing.length > 0) {
    throw new MerkleError(
      `cannot disclose events not present in the range: ${missing.join(', ')}`,
    );
  }

  return {
    disclosureVersion: 1,
    compaction: opts.compaction,
    disclosed,
    keys: opts.keys,
  };
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

/**
 * Verify a disclosure package.
 *
 * Establishes `attested`: the root is validly signed, and the disclosed events
 * sit under it. It establishes NOTHING about undisclosed events beyond their
 * count — which is why `leafCount` is always reported alongside
 * `disclosedCount`. A verifier that hides the denominator is helping to
 * mislead.
 */
export function verifyDisclosure(pkg: DisclosurePackage): DisclosureVerification {
  const issues: DisclosureIssue[] = [];
  const fail = (code: string, message: string, eventId?: string): void => {
    issues.push({ code, message, ...(eventId ? { eventId } : {}) });
  };

  const none = (): DisclosureVerification => ({
    valid: false,
    level: 'none',
    issues,
    merkleRoot: null,
    disclosedCount: pkg.disclosed?.length ?? 0,
    leafCount: null,
  });

  if (pkg.disclosureVersion !== 1) {
    fail('version', `unsupported disclosureVersion ${String(pkg.disclosureVersion)}`);
    return none();
  }

  const compaction = pkg.compaction;
  if (compaction?.eventType !== 'chain_compacted') {
    fail('not-a-compaction', 'package.compaction is not a chain_compacted event');
    return none();
  }
  const payload = compaction.payload as ChainCompactedPayload;

  // --- 1. The compaction event must verify as an ordinary RFC-0002 event ----
  const bytes = canonicalEventBytes(hashable(compaction));
  const recomputed = createHash('sha256').update(bytes).digest('hex');
  if (recomputed !== compaction.eventHash) {
    fail(
      'compaction-hash',
      `compaction eventHash mismatch — recomputed ${recomputed}, stored ${compaction.eventHash}`,
      compaction.eventId,
    );
    return none();
  }

  if (!compaction.signature || !compaction.signedBy) {
    fail(
      'compaction-unsigned',
      'compaction carries no signature — an unsigned compaction attests nothing, it is an unattributed assertion that some range had some root',
      compaction.eventId,
    );
    return none();
  }

  const keyMaterial = pkg.keys?.[compaction.signedBy];
  if (!keyMaterial) {
    fail(
      'compaction-key-missing',
      `no public key supplied for signer "${compaction.signedBy}" — the root signature cannot be checked, so membership cannot be reported as verified`,
      compaction.eventId,
    );
    return none();
  }

  let sigOk = false;
  try {
    sigOk = cryptoVerify(
      null,
      bytes,
      toPublicKey(keyMaterial),
      Buffer.from(compaction.signature, 'base64'),
    );
  } catch (err) {
    fail('compaction-key-unusable', `public key unusable: ${(err as Error).message}`);
    return none();
  }
  if (!sigOk) {
    fail('compaction-signature', 'compaction signature did not verify', compaction.eventId);
    return none();
  }

  // --- 2. Fold each disclosed leaf to the attested root ---------------------
  if (typeof payload.leafCount !== 'number' || payload.leafCount < 1) {
    fail('leaf-count', 'compaction does not declare a valid leafCount — a root without a count is unauditable');
  }
  if (payload.salted && pkg.disclosed.some((d) => !d.salt)) {
    fail(
      'salt-missing',
      'compaction is salted but a disclosed leaf carries no salt — that leaf can never be proved',
    );
  }

  for (const d of pkg.disclosed) {
    if (
      !Number.isInteger(d.leafIndex) ||
      d.leafIndex < 0 ||
      d.leafIndex >= payload.leafCount
    ) {
      fail(
        'leaf-index',
        `leafIndex ${d.leafIndex} is outside [0, ${payload.leafCount})`,
        d.event?.eventId,
      );
      continue;
    }
    const leaf = leafHash(hashable(d.event), d.salt);
    if (!verifyPath(leaf, d.path, payload.merkleRoot)) {
      fail(
        'membership',
        `disclosed event does not fold to the attested root — it was not in this range, or the path is wrong`,
        d.event?.eventId,
      );
    }
  }

  const valid = issues.length === 0;
  return {
    valid,
    level: valid ? 'attested' : 'none',
    issues,
    merkleRoot: payload.merkleRoot,
    disclosedCount: pkg.disclosed.length,
    leafCount: payload.leafCount ?? null,
  };
}

/**
 * Cross-check a compaction against the range it claims to summarize.
 *
 * For a verifier that still HOLDS the underlying events. A mismatch means the
 * compaction event is lying about what it summarizes, and MUST fail — even
 * though every individual event may be perfectly intact. This is the check
 * that catches a compactor swapping a range's contents.
 */
export function verifyAgainstRange(
  compaction: ChainEvent,
  range: ReadonlyArray<ChainEvent>,
  salts?: ReadonlyArray<string | undefined>,
): DisclosureVerification {
  const issues: DisclosureIssue[] = [];
  const payload = compaction.payload as ChainCompactedPayload;

  if (range.length !== payload.leafCount) {
    issues.push({
      code: 'count-mismatch',
      message: `compaction declares leafCount ${payload.leafCount} but the range holds ${range.length} events`,
      eventId: compaction.eventId,
    });
  }

  const recomputedRoot =
    range.length > 0
      ? merkleRoot(range.map((e, i) => leafHash(hashable(e), salts?.[i])))
      : null;

  if (recomputedRoot !== payload.merkleRoot) {
    issues.push({
      code: 'root-mismatch',
      message: `recomputed root ${recomputedRoot ?? '(none)'} does not match the attested root ${payload.merkleRoot} — the compaction is false about what it summarizes`,
      eventId: compaction.eventId,
    });
  }

  const valid = issues.length === 0;
  return {
    valid,
    level: valid ? 'full' : 'none',
    issues,
    merkleRoot: recomputedRoot,
    disclosedCount: range.length,
    leafCount: payload.leafCount ?? null,
  };
}
