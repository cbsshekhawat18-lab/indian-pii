# Changelog

All notable changes to **indian-pii** are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

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
