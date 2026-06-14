/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 *
 *  Optional image/OCR layer. It does NOT perform OCR or bundle any model — the
 *  user supplies OCR output, which this layer normalises and feeds back into the
 *  core string engine, mapping each text hit to pixel boxes for redaction.
 * ========================================================================== */

import { detect } from "../index.js";
import type {
  BoundingBox,
  ImageDetectionResult,
  ImageDetectOptions,
  OcrResult,
  OcrWord,
} from "./types.js";

export * from "./types.js";
export { fromTesseract } from "./adapters/tesseract.js";
export { redactBoxes } from "./redact.js";
export type { Fill2D, RedactOptions } from "./redact.js";

interface WordSpan {
  start: number;
  end: number;
  word: OcrWord;
}

/** Union of one or more boxes; returns null if the list is empty. */
function unionBox(boxes: BoundingBox[]): BoundingBox | null {
  if (boxes.length === 0) return null;
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const b of boxes) {
    if (b.x < minX) minX = b.x;
    if (b.y < minY) minY = b.y;
    if (b.x + b.width > maxX) maxX = b.x + b.width;
    if (b.y + b.height > maxY) maxY = b.y + b.height;
  }
  return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
}

/**
 * Detect Indian PII inside OCR output and resolve each hit to pixel geometry.
 *
 * Scan text is reconstructed by joining `ocr.words` with a single-character
 * `joiner` (default `" "`), recording each word's `[start, end)` character span.
 * Core {@link detect} runs on that text; every hit is mapped back to the OCR
 * words its character range overlaps, producing per-word `boxes`, their union
 * `bbox`, and the mean OCR confidence of those words. Hits that fall only on
 * joiner characters are skipped.
 *
 * @throws RangeError if `joiner` is not exactly one character.
 */
export function detectInImage(
  ocr: OcrResult,
  options: ImageDetectOptions = {}
): ImageDetectionResult[] {
  const joiner = options.joiner ?? " ";
  if (joiner.length !== 1) {
    throw new RangeError("joiner must be exactly one character");
  }

  const words = ocr && Array.isArray(ocr.words) ? ocr.words : [];

  // Reconstruct scan text and record each word's character span.
  let text = "";
  const spans: WordSpan[] = [];
  for (let i = 0; i < words.length; i++) {
    if (i > 0) text += joiner;
    const start = text.length;
    text += words[i]!.text;
    spans.push({ start, end: text.length, word: words[i]! });
  }

  const hits = detect(text, {
    types: options.types,
    requireValid: options.requireValid,
    contextWindow: options.contextWindow,
  });

  const results: ImageDetectionResult[] = [];
  for (const hit of hits) {
    const hitStart = hit.index;
    const hitEnd = hit.index + hit.value.length;

    // Words whose span overlaps the hit's character range.
    const overlapping: OcrWord[] = [];
    for (const s of spans) {
      if (s.start < hitEnd && s.end > hitStart) overlapping.push(s.word);
    }
    if (overlapping.length === 0) continue; // hit landed only on joiner chars

    const boxes = overlapping.map((w) => w.bbox);
    const bbox = unionBox(boxes);
    if (!bbox) continue;

    const confidences = overlapping
      .map((w) => w.confidence)
      .filter((c): c is number => typeof c === "number");
    const ocrConfidence =
      confidences.length > 0
        ? confidences.reduce((a, b) => a + b, 0) / confidences.length
        : undefined;

    results.push({ ...hit, bbox, boxes, ocrConfidence });
  }

  return results;
}
