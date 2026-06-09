/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Public entry point. NOTE: detection and validation check FORMAT and CHECKSUMS
// only — a value that validates is well-formed, not proof that the identifier is
// real, issued, or active. Never treat a passing result as proof of identity.

import type {
  Detector,
  DetectionResult,
  DetectOptions,
  MaskOptions,
} from "./types.js";
import { detectors, detectorMap } from "./detectors/index.js";
import { asString, hasContextNearby } from "./utils/text.js";

export type {
  Detector,
  DetectionResult,
  DetectOptions,
  MaskOptions,
  Category,
  Severity,
} from "./types.js";

export { detectors, detectorMap };

const DEFAULT_CONTEXT_WINDOW = 40;

/** Confidence score for a hit; checksum-validated hits outrank structure-only. */
function scoreConfidence(det: Detector, valid: boolean, hasContext: boolean): number {
  if (det.checksum) return valid ? 0.99 : 0.3;
  let base = valid ? 0.8 : 0.45;
  if (det.contextGated && hasContext) base += 0.1;
  return Math.min(base, 0.95);
}

/**
 * Selects the detectors to run, honouring an optional `types` allowlist.
 */
function selectDetectors(types?: string[]): Detector[] {
  if (!types || types.length === 0) return detectors;
  const allow = new Set(types);
  return detectors.filter((d) => allow.has(d.id));
}

/**
 * Scan `text` for Indian PII. Returns non-overlapping hits; where spans
 * overlap, the highest-confidence hit (checksum-validated beats structure-only)
 * is kept.
 *
 * @param text   The text to scan.
 * @param options.types         Restrict to these detector ids.
 * @param options.requireValid  Only return hits that pass real validation.
 * @param options.contextWindow Characters each side searched for a keyword.
 */
export function detect(text: unknown, options: DetectOptions = {}): DetectionResult[] {
  if (typeof text !== "string" || text.length === 0) return [];
  const window = options.contextWindow ?? DEFAULT_CONTEXT_WINDOW;
  const active = selectDetectors(options.types);
  const candidates: (DetectionResult & { end: number })[] = [];

  for (const det of active) {
    const re = new RegExp(det.regex.source, det.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const value = m[0];
      const index = m.index;
      const end = index + value.length;
      const valid = safeValidate(det, value);

      if (options.requireValid && !valid) continue;

      // Context gate: loose/short patterns only count when a keyword is nearby
      // or the value self-identifies (e.g. a known UPI handle, a +91 prefix).
      let ctx = false;
      if (det.contextGated) {
        const selfId = det.selfIdentifies ? safeSelfId(det, value) : false;
        ctx = selfId || hasContextNearby(text, index, value.length, det.contextHints, window);
        if (!ctx) continue;
      } else {
        ctx = hasContextNearby(text, index, value.length, det.contextHints, window);
      }

      candidates.push({
        type: det.id,
        value,
        index,
        valid,
        confidence: scoreConfidence(det, valid, ctx),
        end,
      });
    }
  }

  return dedupeOverlaps(candidates);
}

/** Resolve overlapping spans, keeping the strongest hit per region. */
function dedupeOverlaps(
  cands: (DetectionResult & { end: number })[]
): DetectionResult[] {
  // Strongest first: confidence, then valid, then longer span, then earlier.
  cands.sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    if (a.valid !== b.valid) return a.valid ? -1 : 1;
    const lenA = a.end - a.index;
    const lenB = b.end - b.index;
    if (lenB !== lenA) return lenB - lenA;
    return a.index - b.index;
  });

  const kept: (DetectionResult & { end: number })[] = [];
  for (const c of cands) {
    const overlaps = kept.some((k) => c.index < k.end && c.end > k.index);
    if (!overlaps) kept.push(c);
  }

  kept.sort((a, b) => a.index - b.index);
  return kept.map(({ end: _end, ...rest }) => rest);
}

function safeValidate(det: Detector, value: string): boolean {
  try {
    return det.validate(value);
  } catch {
    return false;
  }
}

function safeSelfId(det: Detector, value: string): boolean {
  try {
    return det.selfIdentifies ? det.selfIdentifies(value) : false;
  } catch {
    return false;
  }
}

/**
 * Strictly validate a single value against one detector type (checksum or
 * structure). Returns false for unknown types or non-string input — never
 * throws.
 */
export function validate(type: string, value: unknown): boolean {
  const det = detectorMap.get(type);
  if (!det) return false;
  const v = asString(value);
  if (v.length === 0) return false;
  return safeValidate(det, v);
}

/**
 * Mask a single value using its detector's masking rule. Unknown types return
 * the input unchanged; non-string input returns "".
 */
export function maskValue(type: string, value: unknown): string {
  const v = asString(value);
  const det = detectorMap.get(type);
  if (!det) return v;
  if (v.length === 0) return "";
  try {
    return det.mask(v);
  } catch {
    return v;
  }
}

/**
 * Detect all PII in `text` and return a copy with each hit replaced by its
 * masked form. Accepts the same options as {@link detect} plus `maskChar`.
 */
export function mask(text: unknown, options: MaskOptions = {}): string {
  if (typeof text !== "string" || text.length === 0) {
    return typeof text === "string" ? text : "";
  }
  const hits = detect(text, options);
  if (hits.length === 0) return text;

  // Replace from the rightmost hit so earlier indices stay valid.
  let out = text;
  for (let i = hits.length - 1; i >= 0; i--) {
    const h = hits[i]!;
    const det = detectorMap.get(h.type);
    let masked: string;
    try {
      masked = det ? det.mask(h.value) : h.value;
    } catch {
      masked = h.value;
    }
    if (options.maskChar && options.maskChar !== "X") {
      masked = masked.split("X").join(options.maskChar);
    }
    out = out.slice(0, h.index) + masked + out.slice(h.index + h.value.length);
  }
  return out;
}
