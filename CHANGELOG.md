# Changelog

All notable changes to `@saihm/client-pro` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] — 2026-06-25

Additive API release. No wire-format, envelope, or HKDF-domain change; cells
sealed by 0.1.0/0.1.1 open unchanged.

### Added

- `signChallenge(secretKey, message)` — ML-DSA-65 detached signature over an
  onboarding challenge nonce, so a client can prove control of its identity
  during self-onboarding without holding a static token.
- `browser-entry.mjs` — browser ESM entry exposing `deriveIdentity`, `toHex`,
  and `fromHex` for in-page identity generation.

## [0.1.1] — 2026-06-22

Documentation release. No cryptographic, wire-format, or API change; the
published JavaScript is behavior-identical to 0.1.0. The HKDF domain tag and
every envelope format are unchanged, so cells sealed by 0.1.0 open under 0.1.1.

### Added

- README positioning for production adopters: polymorphic cells ("one cell,
  many shapes"), shared memory across fleets of homogeneous or disparate
  agents, cross-client portability, and a compliance map — GDPR (Article 15
  access, Article 17 erasure), CCPA/CPRA, HIPAA, ISO/IEC 27001, SOC 2, EU AI
  Act, NIST AI RMF, and ISO/IEC 42001.
- Companion-package cross-reference to `@saihm/mcp-server`.
- First public source release on GitHub.

### Changed

- Refreshed the npm `description` to match the production positioning.

## [0.1.0] — 2026-06-19

Initial release.

### Added

- Client-side envelope cryptography: ML-DSA-65 (FIPS 204) identity and signing,
  ML-KEM-768 (FIPS 203) authenticated sharing, and a per-cell random data
  encryption key (DEK) under AES-256-GCM, wrapped under a client-held key
  encryption key (KEK).
- Crypto-shred erasure model (GDPR Art. 17, controller-side).
- Out-of-band recipient pinning with key-substitution rejection.
- Built only on `@noble/*` primitives; contains no server-side code.

[Unreleased]: https://github.com/SAIHM-Admin/saihm-client-pro/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/SAIHM-Admin/saihm-client-pro/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/SAIHM-Admin/saihm-client-pro/releases/tag/v0.1.0
