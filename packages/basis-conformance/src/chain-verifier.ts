// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Public reference verifier for RFC-0002 proof event chains.
 *
 * This is the implementation of RFC-0002 §"Verification procedure". Unlike
 * `validateManifest` (which is truth-only/structural and deliberately does
 * NOT touch cryptography), this module actually:
 *
 *   1. Rebuilds each event's canonical-JSON byte string from the hashable
 *      fields (RFC-0002 §"Canonical serialization").
 *   2. Recomputes `eventHash` (sha256) and, when present, `eventHash3`
 *      (sha3-256) over those same bytes, and compares to what was stored.
 *   3. Confirms `previousHash` linkage forms a strictly linear chain, with
 *      `null` at the head.
 *   4. Verifies detached Ed25519 signatures when a public key is supplied
 *      for the event's `signedBy` identity.
 *
 * It is dependency-free beyond `node:crypto` on purpose: an auditor should
 * be able to read this file end to end and believe it.
 *
 * FAIL-CLOSED POSTURE (consistent with the rest of this suite):
 *   - An empty chain is NEVER valid. Zero events is a runner error, not a
 *     pass — the same rule the conformance runner applies to zero tests.
 *   - A signature that is PRESENT but could not be checked (no key supplied,
 *     unsupported key, malformed signature) never silently counts as good.
 *     It is reported in `signaturesUnverified`, and under
 *     `requireSignatures: true` it makes the whole chain invalid.
 *   - `valid: true` means every check that ran passed AND no present-but-
 *     unverifiable signature was ignored under strict mode. It is an
 *     integrity verdict about the record — never a trust or compliance
 *     verdict about the agent.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

// ---------------------------------------------------------------------------
// Canonical serialization (RFC-0002 §"Canonical serialization")
// ---------------------------------------------------------------------------

/**
 * Reference canonicalizer per RFC-0002:
 *   - object keys sorted in ASCII-byte order
 *   - no whitespace
 *   - numbers as the shortest decimal that round-trips (JS `String(n)`)
 *   - finite numbers only — Infinity/NaN throw
 *   - `null` preserved; `undefined` keys omitted
 *
 * Exported so vendor implementations can hash the EXACT same bytes this
 * verifier does. Cross-impl byte equality is the whole point: if two
 * runtimes disagree here, their chains cannot be verified against each other.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical JSON requires finite numbers');
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const v = value as Record<string, unknown>;
    const keys = Object.keys(v)
      .filter((k) => v[k] !== undefined)
      .sort();
    const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonical JSON does not support type ${typeof value}`);
}

/**
 * The subset of an event that is covered by the hash, per RFC-0002:
 * `previousHash`, `eventType`, `agentId` (empty string when absent),
 * `occurredAt`, `payload`. Everything else (`eventId`, `recordedAt`,
 * `signedBy`, `signature`, the hashes themselves, and the shadow-mode trio)
 * is attached AFTER the hash is sealed and is therefore excluded.
 *
 * Returns the canonical JSON string whose UTF-8 bytes are hashed.
 */
export function canonicalEventString(event: {
  previousHash: string | null;
  eventType: string;
  agentId?: string | null;
  occurredAt: string;
  payload: unknown;
}): string {
  return canonicalize({
    agentId: event.agentId ?? '',
    eventType: event.eventType,
    occurredAt: event.occurredAt,
    payload: event.payload,
    previousHash: event.previousHash,
  });
}

/** UTF-8 bytes of the canonical event string — the exact hash/signature input. */
export function canonicalEventBytes(event: Parameters<typeof canonicalEventString>[0]): Buffer {
  return Buffer.from(canonicalEventString(event), 'utf-8');
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * sha3-256 is OPTIONAL in RFC-0002. It is available in Node builds linked
 * against OpenSSL 3; where it is not, we must say so rather than quietly
 * skipping the check.
 */
function sha3_256HexOrNull(bytes: Buffer): string | null {
  try {
    return createHash('sha3-256').update(bytes).digest('hex');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Ed25519 key + signature handling
// ---------------------------------------------------------------------------

/** DER SPKI prefix for an Ed25519 public key (RFC 8410). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const HEX_64 = /^[0-9a-f]{64}$/i;

/**
 * Accept an Ed25519 public key as:
 *   - a PEM SPKI string ("-----BEGIN PUBLIC KEY-----...")
 *   - a raw 32-byte key, hex-encoded (64 hex chars)
 *   - a raw 32-byte key, base64-encoded
 *   - an already-constructed node KeyObject
 *
 * Raw forms are wrapped into DER SPKI so `createPublicKey` accepts them.
 * Throws on anything else — an unparseable key must never degrade into
 * "signature skipped".
 */
export function toEd25519PublicKey(key: string | KeyObject): KeyObject {
  if (typeof key !== 'string') return key;

  const trimmed = key.trim();
  if (trimmed.includes('BEGIN PUBLIC KEY')) {
    return createPublicKey(trimmed);
  }

  let raw: Buffer;
  if (HEX_64.test(trimmed)) {
    raw = Buffer.from(trimmed, 'hex');
  } else {
    raw = Buffer.from(trimmed, 'base64');
  }
  if (raw.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes (got ${raw.length}); ` +
        'supply PEM SPKI, 64-char hex, or base64 of the raw key',
    );
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function decodeSignature(sig: string): Buffer {
  const trimmed = sig.trim();
  const buf = /^[0-9a-f]{128}$/i.test(trimmed)
    ? Buffer.from(trimmed, 'hex')
    : Buffer.from(trimmed, 'base64');
  if (buf.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes (got ${buf.length})`);
  }
  return buf;
}

/**
 * RFC-0002 carries an ambiguity the reference verifier has to face
 * head-on. §"Schema" annotates `signature` as "detached signature over
 * eventHash", while §"Verification procedure" step 5 says to verify "the
 * detached signature over the canonical bytes". Those are different
 * messages and a signature valid under one is invalid under the other.
 *
 * This verifier treats the normative Verification procedure as
 * authoritative and signs/verifies over the CANONICAL BYTES by default.
 * When a signature fails under the primary domain, we retry under the
 * other and, if that succeeds, report `signature-domain-mismatch` — a
 * precise interop diagnostic instead of a bare "bad signature".
 *
 * Tracked for spec erratum; see the note in the package README.
 */
export type SignatureDomain = 'canonical' | 'eventHash';

function signatureMessage(
  domain: SignatureDomain,
  canonicalBytes: Buffer,
  eventHash: string,
): Buffer {
  return domain === 'canonical' ? canonicalBytes : Buffer.from(eventHash, 'utf-8');
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Per-event outcome. `null` fields mean "check did not run". */
export interface EventVerification {
  readonly index: number;
  readonly eventId: string;
  /** Recomputed sha256 matched the stored `eventHash`. */
  readonly hashValid: boolean;
  /** Recomputed sha3-256 matched `eventHash3`; null when absent/unsupported. */
  readonly hash3Valid: boolean | null;
  /** `previousHash` matched the prior event's `eventHash` (or null at head). */
  readonly linkageValid: boolean;
  /**
   * Signature outcome:
   *   'valid'         — verified against the supplied key
   *   'invalid'       — key supplied, signature did not verify
   *   'domain-mismatch' — verified only under the OTHER signature domain
   *   'unverified'    — signature present but no usable key was supplied
   *   'absent'        — no signature on this event
   */
  readonly signature: 'valid' | 'invalid' | 'domain-mismatch' | 'unverified' | 'absent';
  /** Human-readable detail for whichever check failed. */
  readonly problem?: string;
}

/**
 * Superset of the spec's `ChainVerificationResult`. The six spec fields are
 * present verbatim so this is drop-in for any consumer coded against
 * `@vorionsys/basis-spec`; the rest is diagnostic detail.
 */
export interface ChainVerificationReport {
  readonly valid: boolean;
  readonly verifiedEvents: number;
  readonly firstEventId: string;
  readonly lastEventId: string;
  readonly brokenAt?: string;
  readonly error?: string;

  readonly signaturesValid: number;
  readonly signaturesInvalid: number;
  /** Present-but-uncheckable signatures. Non-zero is never silently OK. */
  readonly signaturesUnverified: number;
  readonly hash3Checked: number;
  readonly events: ReadonlyArray<EventVerification>;
}

export interface VerifyChainOptions {
  /**
   * Map of `signedBy` identity → Ed25519 public key. Events whose
   * `signedBy` is absent from this map report `unverified`.
   */
  readonly publicKeys?: Readonly<Record<string, string | KeyObject>>;
  /**
   * When true, any present-but-unverifiable signature invalidates the
   * chain. Default false — but the count is always surfaced either way.
   */
  readonly requireSignatures?: boolean;
  /** Which message the detached signature covers. Default 'canonical'. */
  readonly signatureDomain?: SignatureDomain;
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

interface RawEvent {
  eventId?: unknown;
  eventType?: unknown;
  agentId?: unknown;
  occurredAt?: unknown;
  payload?: unknown;
  previousHash?: unknown;
  eventHash?: unknown;
  eventHash3?: unknown;
  signedBy?: unknown;
  signature?: unknown;
}

function fail(error: string): ChainVerificationReport {
  return {
    valid: false,
    verifiedEvents: 0,
    firstEventId: '',
    lastEventId: '',
    error,
    signaturesValid: 0,
    signaturesInvalid: 0,
    signaturesUnverified: 0,
    hash3Checked: 0,
    events: [],
  };
}

/**
 * Verify a proof event chain end to end per RFC-0002 §"Verification
 * procedure".
 *
 * @param chain  Events in chain order (already JSON-parsed).
 * @param opts   Public keys and strictness settings.
 * @returns A `ChainVerificationReport`. `valid: true` only when every
 *          event's hash recomputed correctly, linkage held from a null
 *          head, and no signature check failed (or was skipped under
 *          `requireSignatures`).
 *
 * This reports on the INTEGRITY OF THE RECORD only. A cryptographically
 * perfect chain of bad decisions verifies just fine — that is the point of
 * a receipt, and it is not a statement about the agent's trustworthiness.
 */
export function verifyChain(
  chain: unknown,
  opts: VerifyChainOptions = {},
): ChainVerificationReport {
  if (!Array.isArray(chain)) {
    return fail('chain must be a JSON array of proof events');
  }
  // Fail-closed: an empty chain is not a vacuous pass.
  if (chain.length === 0) {
    return fail('chain is empty — refusing to report a valid verification (fail-closed)');
  }

  const domain: SignatureDomain = opts.signatureDomain ?? 'canonical';
  const otherDomain: SignatureDomain = domain === 'canonical' ? 'eventHash' : 'canonical';

  // Resolve keys once, up front. A malformed key is a hard error rather
  // than a per-event surprise.
  const keys = new Map<string, KeyObject>();
  for (const [id, key] of Object.entries(opts.publicKeys ?? {})) {
    try {
      keys.set(id, toEd25519PublicKey(key));
    } catch (err) {
      return fail(`public key for "${id}" is unusable: ${(err as Error).message}`);
    }
  }

  const events: EventVerification[] = [];
  let signaturesValid = 0;
  let signaturesInvalid = 0;
  let signaturesUnverified = 0;
  let hash3Checked = 0;
  let brokenAt: string | undefined;
  let verifiedEvents = 0;

  let previousEventHash: string | null = null;

  for (let i = 0; i < chain.length; i++) {
    const ev = chain[i] as RawEvent;
    const eventId = typeof ev?.eventId === 'string' ? ev.eventId : `(index ${i})`;

    // Structural preconditions for the crypto to mean anything.
    if (
      typeof ev?.eventType !== 'string' ||
      typeof ev?.occurredAt !== 'string' ||
      typeof ev?.eventHash !== 'string' ||
      ev?.payload === undefined ||
      !('previousHash' in (ev ?? {}))
    ) {
      events.push({
        index: i,
        eventId,
        hashValid: false,
        hash3Valid: null,
        linkageValid: false,
        signature: 'absent',
        problem:
          'event is missing one of the hashable fields (eventType, occurredAt, payload, previousHash) or eventHash — run `validate` for a full structural report',
      });
      brokenAt = eventId;
      break;
    }

    const prevHash = (ev.previousHash ?? null) as string | null;

    // --- Linkage (RFC-0002 §"Chain linkage") -------------------------------
    const linkageValid = i === 0 ? prevHash === null : prevHash === previousEventHash;
    let problem: string | undefined;
    if (!linkageValid) {
      problem =
        i === 0
          ? `chain head must have previousHash null, got ${JSON.stringify(prevHash)}`
          : `previousHash ${JSON.stringify(prevHash)} does not match prior event's eventHash ${JSON.stringify(previousEventHash)}`;
    }

    // --- Hash recomputation ------------------------------------------------
    let canonicalBytes: Buffer;
    try {
      canonicalBytes = canonicalEventBytes({
        previousHash: prevHash,
        eventType: ev.eventType,
        agentId: typeof ev.agentId === 'string' ? ev.agentId : undefined,
        occurredAt: ev.occurredAt,
        payload: ev.payload,
      });
    } catch (err) {
      events.push({
        index: i,
        eventId,
        hashValid: false,
        hash3Valid: null,
        linkageValid,
        signature: 'absent',
        problem: `payload is not canonicalizable: ${(err as Error).message}`,
      });
      brokenAt = eventId;
      break;
    }

    const recomputed = sha256Hex(canonicalBytes);
    const hashValid = recomputed === ev.eventHash;
    if (!hashValid && !problem) {
      problem = `eventHash mismatch — recomputed ${recomputed}, stored ${ev.eventHash}`;
    }

    let hash3Valid: boolean | null = null;
    if (typeof ev.eventHash3 === 'string') {
      const recomputed3 = sha3_256HexOrNull(canonicalBytes);
      if (recomputed3 === null) {
        hash3Valid = null;
        if (!problem) {
          problem = 'eventHash3 present but sha3-256 is unavailable in this Node build — check not run';
        }
      } else {
        hash3Valid = recomputed3 === ev.eventHash3;
        hash3Checked++;
        if (!hash3Valid && !problem) {
          problem = `eventHash3 mismatch — recomputed ${recomputed3}, stored ${ev.eventHash3}`;
        }
      }
    }

    // --- Signature ---------------------------------------------------------
    let signature: EventVerification['signature'] = 'absent';
    if (typeof ev.signature === 'string' && ev.signature.length > 0) {
      const signer = typeof ev.signedBy === 'string' ? ev.signedBy : '';
      const key = signer ? keys.get(signer) : undefined;
      if (!key) {
        signature = 'unverified';
        signaturesUnverified++;
        if (!problem) {
          problem = signer
            ? `signature present but no public key supplied for signedBy "${signer}"`
            : 'signature present but event has no signedBy identity to resolve a key';
        }
      } else {
        try {
          const sig = decodeSignature(ev.signature);
          const ok = cryptoVerify(
            null,
            signatureMessage(domain, canonicalBytes, ev.eventHash),
            key,
            sig,
          );
          if (ok) {
            signature = 'valid';
            signaturesValid++;
          } else {
            // Retry under the other domain to produce a precise diagnostic.
            const okOther = cryptoVerify(
              null,
              signatureMessage(otherDomain, canonicalBytes, ev.eventHash),
              key,
              sig,
            );
            if (okOther) {
              signature = 'domain-mismatch';
              signaturesInvalid++;
              if (!problem) {
                problem = `signature verifies over '${otherDomain}' but this verifier is checking '${domain}' — signer and verifier disagree on the signed message (RFC-0002 erratum)`;
              }
            } else {
              signature = 'invalid';
              signaturesInvalid++;
              if (!problem) problem = 'Ed25519 signature did not verify';
            }
          }
        } catch (err) {
          signature = 'invalid';
          signaturesInvalid++;
          if (!problem) problem = `signature unusable: ${(err as Error).message}`;
        }
      }
    }

    events.push({
      index: i,
      eventId,
      hashValid,
      hash3Valid,
      linkageValid,
      signature,
      ...(problem ? { problem } : {}),
    });

    const eventOk =
      hashValid &&
      linkageValid &&
      hash3Valid !== false &&
      signature !== 'invalid' &&
      signature !== 'domain-mismatch';

    if (!eventOk) {
      brokenAt = eventId;
      break;
    }

    verifiedEvents++;
    previousEventHash = ev.eventHash;
  }

  const strictFailure = (opts.requireSignatures ?? false) && signaturesUnverified > 0;

  const firstEventId =
    typeof (chain[0] as RawEvent)?.eventId === 'string'
      ? ((chain[0] as RawEvent).eventId as string)
      : '';
  const lastEventId =
    typeof (chain[chain.length - 1] as RawEvent)?.eventId === 'string'
      ? ((chain[chain.length - 1] as RawEvent).eventId as string)
      : '';

  const valid = brokenAt === undefined && verifiedEvents === chain.length && !strictFailure;

  return {
    valid,
    verifiedEvents,
    firstEventId,
    lastEventId,
    ...(brokenAt !== undefined ? { brokenAt } : {}),
    ...(strictFailure
      ? {
          error: `${signaturesUnverified} event(s) carry a signature that could not be verified and requireSignatures is set`,
        }
      : {}),
    signaturesValid,
    signaturesInvalid,
    signaturesUnverified,
    hash3Checked,
    events,
  };
}
