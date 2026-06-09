/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { Detector } from "../types.js";
import { aadhaar, pan, voterId, passport, drivingLicence } from "./identity.js";
import { upiVpa, ifsc, micr, demat, card } from "./financial.js";
import { gstin, tan, cin, din } from "./tax.js";
import { uan, abha, mobileIn, pincode } from "./govt.js";

/**
 * The full detector registry, ordered so that checksum-validated and longer,
 * more-specific detectors come first. On equal confidence this ordering decides
 * which detector wins the de-duplication pass in the engine.
 */
export const detectors: Detector[] = [
  // checksum-validated
  aadhaar,
  card,
  gstin,
  abha,
  // structure-validated (longer / more specific first)
  cin,
  pan,
  tan,
  voterId,
  passport,
  drivingLicence,
  ifsc,
  demat,
  upiVpa,
  // context-gated short / loose patterns
  uan,
  mobileIn,
  micr,
  din,
  pincode,
];

/** Map of detector id → detector for O(1) lookup. */
export const detectorMap: Map<string, Detector> = new Map(
  detectors.map((d) => [d.id, d])
);
