# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `@saihm/client-pro`
(the SAIHM client-side cryptography library), please report it privately so
that we can investigate and remediate before public disclosure.

**Private channel:** architect@saihm.coti.global

Please include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept
- Affected version(s) of `@saihm/client-pro`
- Whether the issue is in the sealing/identity/sharing crypto, the canonical
  wire serialization, or in a dependency
- Your name or handle if you wish to be credited in the fix

We acknowledge reports within **14 days**. We aim to provide an initial
assessment and a fix or mitigation plan within **30 days** for confirmed
vulnerabilities, depending on severity and complexity.

## Scope

In scope:

- The published npm package `@saihm/client-pro` and its source in this
  repository
- The cryptographic envelope: identity derivation, per-cell AES-256-GCM
  sealing, ML-KEM-768 authenticated sharing, signature verification, and the
  canonical wire serialization

Out of scope (please report to the relevant project instead):

- Vulnerabilities in third-party MCP clients (Claude Code, Claude Desktop,
  Cursor, etc.) — report to the client vendor
- Vulnerabilities in the underlying Model Context Protocol — report to
  https://github.com/modelcontextprotocol
- Vulnerabilities in the COTI V2 blockchain network — report to COTI Group
- Vulnerabilities in unrelated open-source dependencies — please report
  upstream and let us know so we can pull a patched version

## Disclosure

We follow a coordinated-disclosure model. Once a fix or mitigation is
available we will:

1. Release a patched version of `@saihm/client-pro` to npm
2. Publish a security advisory on the GitHub repository
3. Credit the reporter (with permission) in the advisory and release notes

## Cryptographic concerns

`@saihm/client-pro` performs every operation that touches plaintext or the
master secret on the client. The primitives are:

- ML-DSA-65 (NIST FIPS-204) for post-quantum agent identity and signing
- ML-KEM-768 (NIST FIPS-203) for post-quantum authenticated sharing
- AES-256-GCM for per-cell confidentiality
- HKDF (RFC 5869) for key derivation
- Implementations from the audited `@noble/*` family

If a vulnerability is in the protocol specification itself rather than this
implementation, please indicate that in your report.

## Thank you

Responsible disclosure protects the broader agent ecosystem. We appreciate
the time and care of security researchers who report issues to us privately.
