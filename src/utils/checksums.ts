/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

/**
 * Luhn (mod-10) check. Used as one part of card validation — never alone, since
 * roughly 1 in 10 random numbers passes it.
 */
export function luhnValid(digits: string): boolean {
  if (!/^[0-9]+$/.test(digits)) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Verhoeff checksum over the dihedral group D5. A real Aadhaar / ABHA number's
// last digit is a Verhoeff check digit, so random N-digit numbers fail ~90% of
// the time — the single biggest cure for "looks 12-digit → Aadhaar" mistakes.
const VERHOEFF_D: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** True only if the all-digit string `num` passes the Verhoeff checksum. */
export function verhoeffValid(num: string): boolean {
  if (!/^[0-9]+$/.test(num)) return false;
  let c = 0;
  const len = num.length;
  for (let i = 0; i < len; i++) {
    const digit = num.charCodeAt(len - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![digit]!]!;
  }
  return c === 0;
}

const GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
 * Computes the GSTIN mod-36 check character for the first 14 chars of an
 * (uppercased) GSTIN. Factor alternates 2,1 from the right.
 */
export function gstinCheckChar(first14: string): string | null {
  if (first14.length !== 14) return null;
  let factor = 2;
  let sum = 0;
  for (let i = 13; i >= 0; i--) {
    const v = GST_CHARS.indexOf(first14[i]!);
    if (v < 0) return null;
    let addend = factor * v;
    factor = factor === 2 ? 1 : 2;
    addend = Math.floor(addend / 36) + (addend % 36);
    sum += addend;
  }
  return GST_CHARS[(36 - (sum % 36)) % 36]!;
}
