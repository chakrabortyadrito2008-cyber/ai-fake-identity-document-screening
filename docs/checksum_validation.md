# Checksum & Identifier Validation Module

## Why this exists

Format regexes only prove a number *looks like* an Aadhaar/PAN number. Deterministic
checksums prove whether it could have been **issued at all**. Fabricated IDs — the
cheapest way to fake an identity document — fail these checks without any model,
network call, or reference data.

## Checks

### Aadhaar — Verhoeff checksum

The Aadhaar number is a 12-digit Verhoeff checksummed identifier; the 12th digit is
the check digit. Validation uses the standard permutation table `p` and
dihedral-group D5 multiplication table `d`. Valid iff the accumulated
`d[p[pos % 8][digit]]` chain over all digits (right to left) ends at 0.

Example: base `23456789123` requires check digit `8`, so `234567891238` passes while
`234567891234` and common placeholder sequences (`123456789012`, `000000000000`,
`111111111111`) all fail.

OCR digit confusion cannot turn a valid number into another *valid* number except
by direct coincidence, so a failed Verhoeff check on a cleanly-OCR'd 12-digit
number is strong, deterministic evidence of a fabricated identifier.

### PAN — structural semantics (format `AAAPA1234A`)

- 4th character = holder type: `P` (person), `C` (company), `H` (HUF), `F` (firm),
  `A` (AOP), `T` (trust), `B` (BOI), `L` (local authority), `J` (artificial
  juridical person), `G` (government)
- 5th character = first letter of the holder's surname / entity name
- 1st three characters = jurisdiction code series

We validate holder-type membership (deterministic) and record the 5th character for
advisory cross-checking against the extracted name field (not scored).

## Evidence calibration

| Signal | Severity | Reliability | Rationale |
|---|---|---|---|
| `id_checksum_invalid` | 30 | 0.95 | Mathematically impossible for a genuine number; below artifact reuse (75) because OCR could in principle mis-read a digit pair |
| `pan_holder_type_invalid` | 25 | 0.9 | Structural impossibility; not a registry lookup |

Both score under dependency root `ocr`, so evidence fusion discounts repeated
OCR-derived signals — one detector can never stack into an automatic HIGH RISK on
its own, consistent with the system's "never declare fraud from a single signal"
doctrine.

## What this does NOT claim

A valid checksum does **not** mean the number was actually issued by UIDAI or the
Income Tax department to the person presenting it. It means the number is
*structurally issuable*. Real issuance status requires an authorised verification
service, which this offline-first system deliberately never assumes.
