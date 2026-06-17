// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Deterministic, platform-independent RFC-3339 timestamp parsing.
 *
 * MUST-FIX (reviewer): the scorer derives ALL time from the events' own
 * `occurredAt` strings — never wall-clock. `Date.parse` / `Date.now` are
 * BANNED here for two reasons:
 *
 *   1. `Date.parse` is host-implementation-defined for many ISO forms and
 *      truncates sub-millisecond precision, so two events 400 microseconds
 *      apart collapse to the same instant and the chain's ordering silently
 *      changes between platforms.
 *   2. `Date.now` is wall-clock and would make the score non-deterministic.
 *
 * This module parses an RFC-3339 / ISO-8601 timestamp with a mandatory
 * offset (`Z` or `±HH:MM`) to an exact **BigInt count of nanoseconds since
 * the Unix epoch**, normalising the offset to UTC. The full sub-second
 * fraction (up to nanosecond, 9 digits) is preserved in the sort key, so
 * distinct instants never merge. Anything the regex cannot represent
 * losslessly returns `null` and the caller fails closed.
 *
 * The calendar arithmetic is Howard Hinnant's `days_from_civil` algorithm
 * carried entirely in BigInt, so it is exact and identical on every
 * platform (no libc, no `Date`).
 */

/**
 * RFC-3339 with mandatory offset. Accepts `T`/`t` and `Z`/`z`. Fractional
 * seconds optional; offset `±HH:MM` required when not `Z`. We intentionally
 * do NOT accept bare local times (no offset) — risk integrity depends on a
 * single canonical instant, so an ambiguous local time fails closed.
 */
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

const NANOS_PER_SEC = 1_000_000_000n;
const SECS_PER_DAY = 86_400n;

/** Days from the civil date (proleptic Gregorian) to/from 1970-01-01. */
function daysFromCivil(yIn: bigint, m: bigint, d: bigint): bigint {
  const y = m <= 2n ? yIn - 1n : yIn;
  const era = (y >= 0n ? y : y - 399n) / 400n;
  const yoe = y - era * 400n; // [0, 399]
  const mp = m > 2n ? m - 3n : m + 9n; // [0, 11]
  const doy = (153n * mp + 2n) / 5n + d - 1n; // [0, 365]
  const doe = yoe * 365n + yoe / 4n - yoe / 100n + doy; // [0, 146096]
  return era * 146097n + doe - 719468n;
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeap(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

/**
 * Parse an RFC-3339 timestamp to exact nanoseconds since the Unix epoch.
 * Returns `null` for anything not losslessly representable (the caller
 * MUST treat `null` as fail-closed).
 */
export function parseOccurredAtNanos(value: unknown): bigint | null {
  if (typeof value !== 'string') return null;
  const m = RFC3339.exec(value);
  if (!m) return null;

  const Y = Number(m[1]);
  const Mo = Number(m[2]);
  const D = Number(m[3]);
  const H = Number(m[4]);
  const Mi = Number(m[5]);
  const S = Number(m[6]);
  const frac = m[7];
  const off = m[8] as string;

  // Calendar range validation — reject impossible dates rather than letting
  // BigInt arithmetic silently normalise them (fail closed).
  if (Mo < 1 || Mo > 12) return null;
  const maxDay =
    Mo === 2 && isLeap(Y) ? 29 : (DAYS_IN_MONTH[Mo - 1] as number);
  if (D < 1 || D > maxDay) return null;
  if (H > 23 || Mi > 59 || S > 59) return null; // no leap-second support; 60 fails closed

  let nanosFrac = 0n;
  if (frac !== undefined) {
    // Reject sub-nanosecond precision rather than truncate it (would merge
    // distinct instants — the exact hole the reviewer flagged).
    if (frac.length > 9) return null;
    nanosFrac = BigInt(frac.padEnd(9, '0'));
  }

  const days = daysFromCivil(BigInt(Y), BigInt(Mo), BigInt(D));
  let secs =
    days * SECS_PER_DAY + BigInt(H) * 3600n + BigInt(Mi) * 60n + BigInt(S);

  if (off !== 'Z' && off !== 'z') {
    const sign = off[0] === '-' ? -1n : 1n;
    const oh = BigInt(off.slice(1, 3));
    const om = BigInt(off.slice(4, 6));
    if (oh > 23n || om > 59n) return null;
    // Subtract the offset to normalise the local time back to UTC.
    secs -= sign * (oh * 3600n + om * 60n);
  }

  return secs * NANOS_PER_SEC + nanosFrac;
}
