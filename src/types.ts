/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

/** Broad grouping of the kind of identifier a detector recognises. */
export type Category =
  | "identity"
  | "financial"
  | "tax"
  | "govt"
  | "health"
  | "contact";

/** Relative sensitivity of the identifier if leaked. */
export type Severity = "low" | "medium" | "high" | "critical";

/**
 * Uniform shape every detector exposes. `validate` performs REAL validation
 * (checksum or strict structure), never a shape-only re-test of the regex.
 */
export interface Detector {
  /** Stable machine id, e.g. "aadhaar". */
  id: string;
  /** Human-readable label, e.g. "Aadhaar number". */
  label: string;
  category: Category;
  severity: Severity;
  /** Global, ReDoS-safe scanning pattern with boundary guards. */
  regex: RegExp;
  /** True only if `value` is a structurally/checksum valid identifier. */
  validate(value: string): boolean;
  /** Returns a privacy-preserving masked stand-in for `value`. */
  mask(value: string): string;
  /** Lowercase substrings that, if nearby, satisfy the context gate. */
  contextHints: string[];

  // --- engine metadata (beyond the minimal interface) ---------------------
  /** Loose/short patterns that must only fire with nearby context. */
  contextGated: boolean;
  /** Whether `validate` enforces a checksum (raises detection confidence). */
  checksum: boolean;
  /**
   * Optional: returns true when the value is self-evidently this type even
   * without surrounding context (e.g. a known UPI handle, a `+91` prefix, or
   * an `IN`-prefixed NSDL demat id). Lets a context-gated detector fire on an
   * unambiguous token.
   */
  selfIdentifies?(value: string): boolean;
}

/** A single hit produced by {@link detect}. */
export interface DetectionResult {
  /** The detector id that matched, e.g. "pan". */
  type: string;
  /** The exact matched substring. */
  value: string;
  /** Start offset of `value` within the scanned text. */
  index: number;
  /** True if `value` passed real validation (checksum/structure). */
  valid: boolean;
  /** 0–1 score; checksum-validated hits outrank structure-only hits. */
  confidence: number;
}

export interface DetectOptions {
  /** Restrict detection to these detector ids. */
  types?: string[];
  /** Only return hits whose `valid` is true. */
  requireValid?: boolean;
  /** Characters on each side searched for a context keyword (default 40). */
  contextWindow?: number;
}

export interface MaskOptions extends DetectOptions {
  /** Character used for redaction (default "X"). */
  maskChar?: string;
}
