/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

/** Safely coerce unknown input to a trimmed string; "" for null/non-string. */
export function asString(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

/** Remove spaces and hyphens (common separators in formatted Indian IDs). */
export function stripSeparators(value: string): string {
  return value.replace(/[\s-]/g, "");
}

/**
 * Mask the alphanumeric characters of `value`, preserving any non-alphanumeric
 * separators (spaces/hyphens), keeping the first `first` and last `last`
 * alphanumeric characters in the clear.
 */
export function maskChars(
  value: string,
  opts: { first?: number; last?: number; ch?: string } = {}
): string {
  const { first = 0, last = 0, ch = "X" } = opts;
  const chars = [...value];
  const alnumIdx: number[] = [];
  for (let i = 0; i < chars.length; i++) {
    if (/[A-Za-z0-9]/.test(chars[i]!)) alnumIdx.push(i);
  }
  const keep = new Set<number>();
  for (let k = 0; k < first && k < alnumIdx.length; k++) keep.add(alnumIdx[k]!);
  for (let k = 0; k < last && k < alnumIdx.length; k++) {
    keep.add(alnumIdx[alnumIdx.length - 1 - k]!);
  }
  return chars
    .map((c, i) => (/[A-Za-z0-9]/.test(c) && !keep.has(i) ? ch : c))
    .join("");
}

/**
 * True if any of `hints` (already lowercase) appears within `window` characters
 * on either side of the span [index, index+length).
 */
export function hasContextNearby(
  text: string,
  index: number,
  length: number,
  hints: readonly string[],
  window: number
): boolean {
  if (hints.length === 0) return false;
  const start = Math.max(0, index - window);
  const end = Math.min(text.length, index + length + window);
  const slice = text.slice(start, end).toLowerCase();
  for (const h of hints) {
    if (slice.includes(h)) return true;
  }
  return false;
}
