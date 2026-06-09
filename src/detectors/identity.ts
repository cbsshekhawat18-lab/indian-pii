/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { Detector } from "../types.js";
import { verhoeffValid } from "../utils/checksums.js";
import { asString, stripSeparators, maskChars } from "../utils/text.js";
import { DL_STATE_CODES, PAN_HOLDER_TYPES } from "../utils/constants.js";

/** 1. Aadhaar — 12 digits, first digit 2–9, Verhoeff check digit. */
export const aadhaar: Detector = {
  id: "aadhaar",
  label: "Aadhaar number",
  category: "identity",
  severity: "critical",
  // 4-4-4 grouping with optional space/hyphen separators, or 12 plain digits.
  regex: /(?<![0-9A-Za-z])[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}(?![0-9A-Za-z])/g,
  checksum: true,
  contextGated: false,
  contextHints: ["aadhaar", "aadhar", "uidai", "आधार", "uid"],
  validate(value) {
    const d = stripSeparators(asString(value));
    if (d.length !== 12) return false;
    if (d[0] === "0" || d[0] === "1") return false;
    return verhoeffValid(d);
  },
  mask(value) {
    return maskChars(asString(value), { last: 4 });
  },
};

/** 2. PAN — ^[A-Z]{5}[0-9]{4}[A-Z]$, 4th char is the holder type. */
export const pan: Detector = {
  id: "pan",
  label: "PAN (Permanent Account Number)",
  category: "identity",
  severity: "high",
  regex: /(?<![0-9A-Za-z])[A-Za-z]{5}[0-9]{4}[A-Za-z](?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["pan", "permanent account"],
  validate(value) {
    const v = asString(value).toUpperCase();
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(v)) return false;
    return PAN_HOLDER_TYPES.has(v[3]!);
  },
  mask(value) {
    return maskChars(asString(value), { first: 1, last: 1 });
  },
};

/** 3. Voter ID (EPIC) — ^[A-Z]{3}[0-9]{7}$, structure only. */
export const voterId: Detector = {
  id: "voter_id",
  label: "Voter ID (EPIC)",
  category: "identity",
  severity: "high",
  regex: /(?<![0-9A-Za-z])[A-Za-z]{3}[0-9]{7}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["voter", "epic", "election", "electoral"],
  validate(value) {
    return /^[A-Z]{3}[0-9]{7}$/.test(asString(value).toUpperCase());
  },
  mask(value) {
    return maskChars(asString(value), { first: 3 });
  },
};

/** 4. Passport (Indian) — ^[A-PR-WY][0-9]{7}$, structure only. */
export const passport: Detector = {
  id: "passport",
  label: "Indian passport number",
  category: "identity",
  severity: "high",
  regex: /(?<![0-9A-Za-z])[A-PR-WYa-pr-wy][0-9]{7}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["passport"],
  validate(value) {
    return /^[A-PR-WY][0-9]{7}$/.test(asString(value).toUpperCase());
  },
  mask(value) {
    return maskChars(asString(value), { first: 1, last: 2 });
  },
};

/**
 * 5. Driving licence — 2-letter state/RTO code + 11–14 digits (with an optional
 * space after the state and RTO blocks). Structure only.
 */
export const drivingLicence: Detector = {
  id: "driving_licence",
  label: "Driving licence number",
  category: "identity",
  severity: "high",
  regex:
    /(?<![0-9A-Za-z])[A-Za-z]{2}[\s-]?[0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4,8}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["driving", "licence", "license", "dl no", "dl number", "rto"],
  validate(value) {
    const v = asString(value).toUpperCase();
    const m = /^([A-Z]{2})[\s-]?([0-9]{2})[\s-]?([0-9]{4})[\s-]?([0-9]{4,8})$/.exec(v);
    if (!m) return false;
    if (!DL_STATE_CODES.has(m[1]!)) return false;
    const digits = m[2]! + m[3]! + m[4]!;
    // RTO(2) + year(4) + sequence(5..7) → 11–14 digits total in practice.
    return digits.length >= 11 && digits.length <= 14;
  },
  mask(value) {
    return maskChars(asString(value), { first: 4, last: 2 });
  },
};
