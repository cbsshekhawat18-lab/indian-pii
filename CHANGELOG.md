# Changelog

All notable changes to **indian-pii** are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Optional, dependency-free image/OCR layer published at the subpath
  `indian-pii/image`:
  - `detectInImage(ocr, options?)` — reconstructs scan text from OCR words, runs
    the existing core `detect()`, and maps each hit to pixel boxes (`bbox`,
    per-word `boxes`, mean `ocrConfidence`).
  - `fromTesseract(data)` — pure transform of Tesseract.js `recognize()` output
    into the normalised `OcrResult` shape (imports nothing).
  - `redactBoxes(ctx, results, options?)` — paints opaque boxes over detected PII
    against a structural `Fill2D` canvas interface (works with browser canvas and
    node-canvas without importing either).
  - `RegionDetector` / `ObjectRegion` types as a future seam for object
    detection (faces/signatures/QR) — no model ships with core.
- The core string API is unchanged and remains string-only with zero runtime
  dependencies.

## [0.1.0] — 2026-06-09

### Added

- Initial release with 18 Indian PII detectors:
  - **Identity:** Aadhaar, PAN, Voter ID (EPIC), Passport, Driving Licence
  - **Financial:** UPI VPA, IFSC, MICR, Demat, Payment Card
  - **Tax / Business:** GSTIN, TAN, CIN, DIN
  - **Govt / Health / Contact:** UAN, ABHA, Indian Mobile, Pincode
- Real validation (not shape-only):
  - Verhoeff checksum for Aadhaar and ABHA
  - GSTN mod-36 check digit + state-code range for GSTIN
  - Luhn + network IIN prefix + exact length for payment cards
  - Strict structural validation for the remaining detectors
- Public API: `detect`, `validate`, `mask`, `maskValue`, `detectors`.
- Context gating for loose/short patterns (MICR, DIN, UAN, mobile, pincode, and
  the bare CDSL demat form) to suppress false positives in free text.
- Boundary safety, input safety (never throws), and ReDoS-safe linear regexes.
- Zero runtime dependencies. ESM + CJS builds with TypeScript declarations.
