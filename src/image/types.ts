/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { DetectionResult } from "../types.js";

/** A pixel rectangle, top-left origin. */
export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** A single recognised word and where it sits in the image. */
export interface OcrWord {
  text: string;
  bbox: BoundingBox;
  /** Optional OCR confidence in the range 0–1. */
  confidence?: number;
}

/** Normalised output of any OCR engine, ready for {@link detectInImage}. */
export interface OcrResult {
  words: OcrWord[];
  imageWidth?: number;
  imageHeight?: number;
}

/**
 * A region returned by an (external) object detector — e.g. a face, signature,
 * or QR code. This is a forward-looking seam: core ships **no** object-detection
 * model. Bring your own detector that satisfies {@link RegionDetector}.
 */
export interface ObjectRegion {
  label: string;
  bbox: BoundingBox;
  /** Optional confidence in the range 0–1. */
  confidence?: number;
}

/**
 * The contract a future/external object detector should implement. Intentionally
 * unimplemented here — no model is bundled, keeping the package dependency-free.
 * The `image` argument is left as `unknown` so this layer never depends on a DOM
 * or any image type.
 */
export interface RegionDetector {
  detectRegions(image: unknown): Promise<ObjectRegion[]>;
}

/**
 * A core {@link DetectionResult} enriched with image geometry: the union
 * {@link BoundingBox} of the hit, the per-word `boxes` it spans, and the mean
 * OCR confidence of those words (when available).
 */
export interface ImageDetectionResult extends DetectionResult {
  bbox: BoundingBox;
  boxes: BoundingBox[];
  ocrConfidence?: number;
}

/** Options for {@link detectInImage}. Mirrors core detect options plus `joiner`. */
export interface ImageDetectOptions {
  types?: string[];
  requireValid?: boolean;
  contextWindow?: number;
  /**
   * Single character inserted between OCR words when reconstructing scan text
   * (default `" "`). Must be exactly one character so word spans stay aligned.
   */
  joiner?: string;
}
