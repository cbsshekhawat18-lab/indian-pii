/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { OcrResult } from "../types.js";

// Minimal local shape of Tesseract.js's recognize() result `data`. We import
// nothing from tesseract.js — this is a pure transform over a plain object, so
// the package stays dependency-free and the user supplies their own OCR run.
interface TesseractBBox {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}
interface TesseractWord {
  text?: string;
  bbox?: TesseractBBox | null;
  confidence?: number;
}
interface TesseractData {
  words?: TesseractWord[] | null;
  width?: number;
  height?: number;
}

/**
 * Convert the `data` object returned by Tesseract.js `worker.recognize()` into a
 * normalised {@link OcrResult}.
 *
 * - corner coords `{x0,y0,x1,y1}` → top-left `{x,y,width,height}`
 * - confidence `0–100` → `0–1` (clamped)
 * - words with empty/whitespace text are dropped
 * - missing/null input is tolerated and yields an empty result
 */
export function fromTesseract(data: TesseractData | null | undefined): OcrResult {
  const words: OcrResult["words"] = [];
  const list = data && Array.isArray(data.words) ? data.words : [];

  for (const w of list) {
    if (!w) continue;
    const text = typeof w.text === "string" ? w.text.trim() : "";
    if (text.length === 0) continue;
    const b = w.bbox;
    if (!b) continue;

    const x = Number(b.x0);
    const y = Number(b.y0);
    const width = Number(b.x1) - x;
    const height = Number(b.y1) - y;
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(width) || !Number.isFinite(height)) {
      continue;
    }

    const word: OcrResult["words"][number] = { text, bbox: { x, y, width, height } };
    if (typeof w.confidence === "number" && Number.isFinite(w.confidence)) {
      word.confidence = Math.max(0, Math.min(1, w.confidence / 100));
    }
    words.push(word);
  }

  const result: OcrResult = { words };
  if (data && typeof data.width === "number") result.imageWidth = data.width;
  if (data && typeof data.height === "number") result.imageHeight = data.height;
  return result;
}
