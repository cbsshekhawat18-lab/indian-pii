/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import { describe, it, expect } from "vitest";
import {
  fromTesseract,
  detectInImage,
  redactBoxes,
  type Fill2D,
  type OcrResult,
} from "../src/image/index.js";

describe("fromTesseract", () => {
  it("converts corner coords to top-left boxes and rescales confidence", () => {
    const data = {
      words: [
        { text: "PAN", bbox: { x0: 10, y0: 20, x1: 60, y1: 40 }, confidence: 95 },
      ],
      width: 800,
      height: 600,
    };
    const out = fromTesseract(data);
    expect(out.words).toHaveLength(1);
    expect(out.words[0]).toEqual({
      text: "PAN",
      bbox: { x: 10, y: 20, width: 50, height: 20 },
      confidence: 0.95,
    });
    expect(out.imageWidth).toBe(800);
    expect(out.imageHeight).toBe(600);
  });

  it("drops empty/whitespace words and tolerates missing/null input", () => {
    const data = {
      words: [
        { text: "  ", bbox: { x0: 0, y0: 0, x1: 5, y1: 5 }, confidence: 80 },
        { text: "ABCPK1234Z", bbox: { x0: 1, y0: 2, x1: 11, y1: 12 } },
        { text: "x", bbox: null, confidence: 50 },
      ],
    };
    const out = fromTesseract(data);
    expect(out.words).toHaveLength(1);
    expect(out.words[0]!.text).toBe("ABCPK1234Z");
    expect(out.words[0]!.confidence).toBeUndefined(); // none provided

    expect(fromTesseract(null).words).toEqual([]);
    expect(fromTesseract(undefined).words).toEqual([]);
    expect(fromTesseract({} as never).words).toEqual([]);
  });
});

describe("detectInImage", () => {
  // Fabricated Aadhaar 234567890124 (Verhoeff-valid) split across three words.
  const ocr: OcrResult = {
    words: [
      { text: "Aadhaar", bbox: { x: 0, y: 0, width: 70, height: 20 }, confidence: 0.99 },
      { text: "2345", bbox: { x: 80, y: 0, width: 40, height: 20 }, confidence: 0.9 },
      { text: "6789", bbox: { x: 130, y: 0, width: 40, height: 20 }, confidence: 0.8 },
      { text: "0124", bbox: { x: 180, y: 0, width: 40, height: 20 }, confidence: 0.7 },
    ],
  };

  it("resolves a split Aadhaar to a valid hit with 3 boxes and the union bbox", () => {
    const results = detectInImage(ocr);
    const aadhaar = results.find((r) => r.type === "aadhaar");
    expect(aadhaar).toBeTruthy();
    expect(aadhaar!.valid).toBe(true);
    expect(aadhaar!.value).toBe("2345 6789 0124");
    expect(aadhaar!.boxes).toHaveLength(3);
    expect(aadhaar!.bbox).toEqual({ x: 80, y: 0, width: 140, height: 20 });
    // mean of the three number-word confidences (0.9, 0.8, 0.7)
    expect(aadhaar!.ocrConfidence).toBeCloseTo(0.8, 5);
  });

  it("throws RangeError when joiner is not exactly one character", () => {
    expect(() => detectInImage(ocr, { joiner: "" })).toThrow(RangeError);
    expect(() => detectInImage(ocr, { joiner: "  " })).toThrow(RangeError);
  });

  it("honours requireValid", () => {
    // Bad checksum (…0123) — shape matches, validation fails.
    const badOcr: OcrResult = {
      words: [
        { text: "2345", bbox: { x: 0, y: 0, width: 40, height: 20 } },
        { text: "6789", bbox: { x: 50, y: 0, width: 40, height: 20 } },
        { text: "0123", bbox: { x: 100, y: 0, width: 40, height: 20 } },
      ],
    };
    const loose = detectInImage(badOcr);
    expect(loose.find((r) => r.type === "aadhaar")?.valid).toBe(false);
    const strict = detectInImage(badOcr, { requireValid: true });
    expect(strict.find((r) => r.type === "aadhaar")).toBeUndefined();
  });
});

describe("redactBoxes", () => {
  function makeCtx() {
    const calls: { x: number; y: number; w: number; h: number }[] = [];
    const ctx: Fill2D = {
      fillStyle: null,
      fillRect: (x, y, w, h) => calls.push({ x, y, w, h }),
    };
    return { ctx, calls };
  }

  const results = detectInImage({
    words: [
      { text: "Aadhaar", bbox: { x: 0, y: 0, width: 70, height: 20 } },
      { text: "2345", bbox: { x: 80, y: 0, width: 40, height: 20 } },
      { text: "6789", bbox: { x: 130, y: 0, width: 40, height: 20 } },
      { text: "0124", bbox: { x: 180, y: 0, width: 40, height: 20 } },
    ],
  });

  it("draws one padded union box by default", () => {
    const { ctx, calls } = makeCtx();
    const n = redactBoxes(ctx, results); // default padding 2
    expect(n).toBe(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ x: 78, y: -2, w: 144, h: 24 });
    expect(ctx.fillStyle).toBe("#000");
  });

  it("draws per-word boxes when perWord is set", () => {
    const { ctx, calls } = makeCtx();
    const n = redactBoxes(ctx, results, { perWord: true, padding: 0, color: "red" });
    expect(n).toBe(3);
    expect(calls).toHaveLength(3);
    expect(calls[0]).toEqual({ x: 80, y: 0, w: 40, h: 20 });
    expect(ctx.fillStyle).toBe("red");
  });
});
