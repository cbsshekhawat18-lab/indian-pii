/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { BoundingBox, ImageDetectionResult } from "./types.js";

/**
 * The minimal structural slice of a 2D canvas context this module needs. Both
 * the browser `CanvasRenderingContext2D` and node-canvas satisfy it, so we never
 * import (or depend on) either.
 */
export interface Fill2D {
  fillStyle: unknown;
  fillRect(x: number, y: number, width: number, height: number): void;
}

export interface RedactOptions {
  /** Fill colour applied to `ctx.fillStyle` (default "#000"). */
  color?: string;
  /** Pixels added on every side of each box (default 2). */
  padding?: number;
  /** Paint each spanned word box instead of the union bbox (default false). */
  perWord?: boolean;
}

/**
 * Paint opaque rectangles over detected PII regions and return how many boxes
 * were drawn. By default it fills the union {@link BoundingBox} of each hit; set
 * `perWord` to fill the individual word boxes instead.
 */
export function redactBoxes(
  ctx: Fill2D,
  results: ImageDetectionResult[],
  options: RedactOptions = {}
): number {
  const { color = "#000", padding = 2, perWord = false } = options;
  ctx.fillStyle = color;

  let count = 0;
  for (const r of results) {
    const boxes: BoundingBox[] = perWord ? r.boxes : [r.bbox];
    for (const b of boxes) {
      if (!b) continue;
      ctx.fillRect(b.x - padding, b.y - padding, b.width + padding * 2, b.height + padding * 2);
      count++;
    }
  }
  return count;
}
