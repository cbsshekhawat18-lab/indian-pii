/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

/**
 * Two-letter RTO/state codes used at the start of a driving licence number.
 * Covers all states/UTs plus common aliases (OD/OR for Odisha, UK/UA for
 * Uttarakhand, TS/TG for Telangana).
 */
export const DL_STATE_CODES = new Set<string>(
  (
    "AN AP AR AS BR CG CH DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP " +
    "MZ NL OD OR PB PY RJ SK TN TR TS TG UK UA UP WB"
  ).split(" ")
);

/**
 * State/UT codes used inside a CIN (registrar-of-companies jurisdiction), as
 * two-letter alpha codes.
 */
export const CIN_STATE_CODES = new Set<string>(
  (
    "AN AP AR AS BR CH CG DL DN GA GJ HP HR JH JK KA KL MH ML MN MP MZ NL OD " +
    "OR PB PY RJ SK TN TG TR UK UP UR WB DD LD"
  ).split(" ")
);

/**
 * Known UPI PSP handles (the part after `@`). A VPA whose handle is in this set
 * is treated as UPI without needing nearby context. The list is non-exhaustive
 * by design; unknown handles still match when UPI/VPA wording is nearby.
 */
export const UPI_HANDLES = new Set<string>(
  (
    "oksbi okhdfcbank okicici okaxis ybl ibl axl apl upi paytm ptaxis ptsbi " +
    "pthdfc ptyes fbl sbi hdfcbank icici axisbank kotak indus federal rbl " +
    "uboi pockets freecharge airtel jio yapl rapl abfspay waicici waaxis " +
    "okbizaxis yescred idfcbank jupiteraxis slc tapicici barodampay cnrb " +
    "yesbank dbs hsbc pnb cbin cboi"
  ).split(" ")
);

/** Holder-type characters valid as the 4th character of a PAN. */
export const PAN_HOLDER_TYPES = new Set<string>("PCHFATBLJGE".split(""));

/** Ownership-type segments valid in the last alpha block of a CIN. */
export const CIN_OWNERSHIP = new Set<string>(
  (
    "PTC PLC GOI GAP GAT NPL FLC FTC ULL ULT OPC SGC FDI"
  ).split(" ")
);
