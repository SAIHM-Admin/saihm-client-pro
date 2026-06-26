# @saihm/client-pro

Client-side envelope cryptography for **SAIHM non-custodial memory**.

This library performs every cryptographic operation that touches your plaintext or your master
secret **on the client**. SAIHM's runtime stores, anchors, shares, and bills over the resulting
ciphertext **blind** — it never holds your keys and cannot read your memory.

- **Post-quantum identity & signing** — ML-DSA-65 (FIPS 204).
- **Post-quantum authenticated sharing** — ML-KEM-768 (FIPS 203), KEM-then-AEAD.
- **Per-cell confidentiality** — a fresh random AES-256-GCM data-encryption key (DEK) per cell,
  itself AEAD-wrapped under a client-held key-encryption key (KEK).
- **Crypto-shred erasure** — because each DEK is random and persisted only in wrapped form on the
  SAIHM side, destroying that wrapped DEK makes the cell undecryptable (GDPR Art. 17, controller-side).
- **Clean-room** — built only on [`@noble`](https://paulmillr.com/noble/) primitives
  (`@noble/post-quantum`, `@noble/ciphers`, `@noble/hashes`). No network, no storage, no platform code.

> **Key loss is unrecoverable by design.** If you lose your master secret (and therefore your KEK),
> your wrapped DEKs cannot be opened — by you or by anyone, including SAIHM. This is the cost of true
> non-custody. Back up your master secret securely.

## Install

```sh
npm install @saihm/client-pro
```

## Usage

```ts
import {
  deriveIdentity,
  sealCell,
  verifyEnvelope,
  openCell,
  shareCell,
  unwrapSharedDek,
  openCellWithDek,
  verifyIdentityRecord,
} from '@saihm/client-pro';

// 1. Derive a deterministic identity from a >=32-byte master secret you hold.
const me = deriveIdentity(myMasterSecret);
//  me.agentIdHash      -> your public identifier (= sha256(ML-DSA public key))
//  me.identityRecord   -> publish to SAIHM (public keys + self-signature)
//  me.kek / me.mldsaSecretKey / me.mlkemSecretKey -> NEVER leave this process

// 2. Encrypt a cell. `seq` is the server-issued monotonic counter for this cell.
const env = sealCell({
  plaintext: new TextEncoder().encode('remember this'),
  kek: me.kek,
  mldsaSecretKey: me.mldsaSecretKey,
  mldsaPubKey: me.mldsaPubKey,
  agentIdHash: me.agentIdHash,
  cellId: 'note-1',
  seq: 1n,
  tier: 'PRO',
});
// `env` is the blind envelope SAIHM stores. SAIHM can verifyEnvelope(env) but cannot open it.

// 3. Read it back (client-side).
const plaintext = openCell(env, me.kek);

// 4. Share a cell with another agent, authenticated and end-to-end.
//    Pin the recipient's agentIdHash out-of-band; the library rejects directory key-substitution.
verifyIdentityRecord(recipientRecord, recipientAgentIdHash); // throws KeySubstitutionError on tamper
const share = shareCell({
  envelope: env,
  sharerKek: me.kek,
  sharerMldsaSecretKey: me.mldsaSecretKey,
  sharerAgentIdHash: me.agentIdHash,
  recipientRecord,
  recipientPinnedAgentIdHash: recipientAgentIdHash,
});
// recipient side (the grantee holds its own identity `recipient`; the sharer's ML-DSA public key
// is pinned out-of-band as `sharerPinnedMldsaPubKey` — sharer authentication is mandatory):
const dek = unwrapSharedDek({
  share,
  recipientMlkemSecretKey: recipient.mlkemSecretKey,
  recipientAgentIdHash: recipient.agentIdHash,
  sharerPinnedMldsaPubKey,
});
const shared = openCellWithDek(env, dek);
```

## Security model

| Property                 | Guarantee                                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------- |
| Confidentiality vs SAIHM | SAIHM holds ciphertext + wrapped DEKs + public keys only; no key able to decrypt.                         |
| Integrity / authenticity | Every envelope is ML-DSA-65-signed over its full contents, including the sequence number.                 |
| Anti-replay / rollback   | The signed, server-issued monotonic `seq` is rejected server-side if not strictly increasing.             |
| Tenant isolation         | State is namespaced by the public `agentIdHash`; a different secret yields a different KEK and namespace. |
| Authenticated sharing    | Recipient public keys are pinned out-of-band and checked before any secret is bound to them.              |
| Erasure                  | Destroying the SAIHM-side wrapped DEK crypto-shreds the cell.                                             |

AES-256-GCM wrap operations use random 96-bit nonces under a reused KEK, well within
NIST SP 800-38D guidance for realistic per-identity write volumes. ML-DSA signatures are hedged
(randomized); they verify deterministically but are not byte-reproducible.

## One cell, many shapes

A SAIHM cell is polymorphic. Store a fact, a JSON record, a table row, a
transcript, or a binary reference once, and read it back in whatever shape the
asking agent needs — one encrypted unit instead of a stack of formats.

## A shared memory layer for fleets of agents

Bind many agents — homogeneous or disparate — to one cryptographically
access-controlled memory. A single identity's memory layer can serve several
different LLM agents at once, so the memory is **portable across every AI
client** and **survives any single vendor's product changes**: when a model or
product is retired, the memory it relied on is not lost with it.

## Built for the people who have to sign off

- **Your keys, not the vendor's.** Every operation that touches plaintext or your
  master secret runs client-side; the SAIHM operator stays blind.
- **A delete you can prove.** Crypto-shred erasure destroys the key that decrypts
  the cell, and the destruction is anchored on a public chain (GDPR Art. 17).
- **A history nobody can quietly rewrite.** Every envelope is post-quantum-signed
  over its full contents, including the monotonic sequence number.
- **Share one record, revoke in one step.** Authenticated and end-to-end, with
  out-of-band recipient pinning.

These map onto the obligations your reviewers already track — GDPR (the
Article 15 access right and the Article 17 right to erasure), CCPA/CPRA, HIPAA,
ISO/IEC 27001 and SOC 2 — alongside the AI-specific frameworks now taking shape:
the EU AI Act, the NIST AI Risk Management Framework and ISO/IEC 42001. Written
for CISOs, DPOs, and anyone comparing AI-memory tools.

## Companion packages

| Package                                                                | Use it for                                                                                                                      |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **`@saihm/client-pro`** (this package)                                 | Production client-side cryptography: sealing, opening, authenticated sharing, and provable erasure — performed on your machine. |
| [`@saihm/mcp-server`](https://www.npmjs.com/package/@saihm/mcp-server) | The open MCP client that exposes the eight SAIHM tools to any MCP-capable AI agent.                                             |

> Pair it with [`@saihm/mcp-server-pro`](https://www.npmjs.com/package/@saihm/mcp-server-pro) — the production, non-custodial **stdio MCP server** that seals every cell with this package, then stores ciphertext at the blind SAIHM endpoint.

## Learn more

- **See it run — live demos:** <https://citw2.github.io/saihm-demos/> (offline, one command each, no account)
- **Token benchmark** — bounded recall vs transcript-resend cut input tokens **62.8%–85.9%** (up to ~86%), open & reproducible: <https://github.com/citw2/saihm-token-benchmark>
- [AI memory needs a standard](https://saihm.coti.global/blog/2026-05-18-ai-memory-needs-a-standard)
- [What makes SAIHM different](https://saihm.coti.global/blog/2026-05-31-what-makes-saihm-different)
- **Join the protocol — <https://saihm.coti.global>**

## License

Apache-2.0 © SAIHM
