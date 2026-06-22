// Per-cell envelope crypto. A fresh RANDOM DEK encrypts each cell; the DEK's only persisted
// form is `wrappedDek` (AEAD-wrapped under the client KEK). SAIHM stores the envelope blind:
// it can verify the signature but holds no key to read `ciphertext` or unwrap `wrappedDek`.
// GDPR Art.17 crypto-shred = destroy the SAIHM-side `wrappedDek` (the DEK was random and is
// derivable from nothing else).

import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { utf8, concat, ctEqual } from './bytes.js';
import { D_SHARD_NONCE } from './domains.js';
import { SCHEMA_ENV, serializeForSigning, cellAad, wrapAad } from './wire.js';
import type { BlindEnvelope, UnsignedEnvelope, PublicMeta } from './wire.js';

const DEK_BYTES = 32;
const KEK_BYTES = 32;
const GCM_NONCE_BYTES = 12;

export interface SealParams {
  readonly plaintext: Uint8Array;
  readonly kek: Uint8Array; // 32 — client-held
  readonly mldsaSecretKey: Uint8Array;
  readonly mldsaPubKey: Uint8Array;
  readonly agentIdHash: Uint8Array; // must equal sha256(mldsaPubKey)
  readonly cellId: string;
  readonly seq: bigint; // server-issued monotonic
  readonly tier: string;
  readonly now?: bigint; // injectable clock (tests)
}

export function sealCell(p: SealParams): BlindEnvelope {
  if (!ctEqual(sha256(p.mldsaPubKey), p.agentIdHash)) {
    throw new Error('agentIdHash must equal sha256(mldsaPubKey)');
  }
  if (p.kek.length !== KEK_BYTES) throw new Error('kek must be 32 bytes (AES-256)');
  const dek = randomBytes(DEK_BYTES);
  try {
    // Nonce = HKDF of the random, single-use DEK => unique per encryption. The DEK is the only
    // keying input and is never reused, so the bare domain string (no separation tag) is
    // sufficient here: no cross-derivation collision is possible.
    const nonce = hkdf(sha256, dek, undefined, utf8(D_SHARD_NONCE), GCM_NONCE_BYTES);
    const aad = cellAad({
      agentIdHash: p.agentIdHash,
      cellId: p.cellId,
      seq: p.seq,
      schemaVer: SCHEMA_ENV,
    });
    const ciphertext = gcm(dek, nonce, aad).encrypt(p.plaintext);
    const commitmentHash = sha256(ciphertext);

    const wrapNonce = randomBytes(GCM_NONCE_BYTES);
    const wDekCt = gcm(
      p.kek,
      wrapNonce,
      wrapAad({ agentIdHash: p.agentIdHash, cellId: p.cellId, seq: p.seq, schemaVer: SCHEMA_ENV }),
    ).encrypt(dek);
    const wrappedDek = concat(wrapNonce, wDekCt);

    const publicMeta: PublicMeta = {
      tier: p.tier,
      createdAt: p.now ?? BigInt(Date.now()),
      commitmentHash,
    };
    const unsigned: UnsignedEnvelope = {
      schemaVer: SCHEMA_ENV,
      agentIdHash: p.agentIdHash,
      cellId: p.cellId,
      seq: p.seq,
      ciphertext,
      nonce,
      wrappedDek,
      mldsaPubKey: p.mldsaPubKey,
      publicMeta,
    };
    const mldsaSig = ml_dsa65.sign(serializeForSigning(unsigned), p.mldsaSecretKey);
    return { ...unsigned, mldsaSig };
  } finally {
    dek.fill(0); // best-effort scrub; the returned envelope never references `dek`
  }
}

/**
 * Blind verification — exactly what SAIHM runs before persist/anchor. True iff:
 *  (1) the identity binding holds: sha256(mldsaPubKey) == agentIdHash;
 *  (2) the ML-DSA signature is valid over the full record; and
 *  (3) commitmentHash actually commits to the stored ciphertext: sha256(ciphertext) == commitmentHash.
 * Check (3) is required so that the SAIHM-operated on-chain anchor (which commits commitmentHash)
 * is a sound tamper-evidence commitment to the bytes SAIHM stores — even against a signer that
 * emits a validly-signed envelope whose commitmentHash lies about its ciphertext.
 */
export function verifyEnvelope(e: BlindEnvelope): boolean {
  try {
    if (!ctEqual(sha256(e.mldsaPubKey), e.agentIdHash)) return false;
    if (!ml_dsa65.verify(e.mldsaSig, serializeForSigning(e), e.mldsaPubKey)) return false;
    return ctEqual(sha256(e.ciphertext), e.publicMeta.commitmentHash);
  } catch {
    // Total predicate over UNTRUSTED input: any malformed field (e.g. an out-of-uint64 seq or
    // createdAt that fails canonical serialization) means the envelope is invalid => fail closed.
    // The blind server runs this on every write; it MUST NOT throw (no unhandled-exception DoS).
    return false;
  }
}

/** Unwrap the per-cell DEK using the client-held KEK. CLIENT-SIDE ONLY. Throws on wrong KEK. */
export function unwrapDek(e: BlindEnvelope, kek: Uint8Array): Uint8Array {
  if (kek.length !== KEK_BYTES) throw new Error('kek must be 32 bytes (AES-256)');
  if (e.wrappedDek.length <= GCM_NONCE_BYTES) throw new Error('wrappedDek too short / destroyed');
  const wrapNonce = e.wrappedDek.subarray(0, GCM_NONCE_BYTES);
  const wDekCt = e.wrappedDek.subarray(GCM_NONCE_BYTES);
  return gcm(
    kek,
    wrapNonce,
    wrapAad({ agentIdHash: e.agentIdHash, cellId: e.cellId, seq: e.seq, schemaVer: e.schemaVer }),
  ).decrypt(wDekCt);
}

/** Open with a known DEK (recipient path after share-unwrap; or owner after unwrapDek). */
export function openCellWithDek(e: BlindEnvelope, dek: Uint8Array): Uint8Array {
  if (dek.length !== DEK_BYTES) throw new Error('dek must be 32 bytes (AES-256)');
  const aad = cellAad({ agentIdHash: e.agentIdHash, cellId: e.cellId, seq: e.seq, schemaVer: e.schemaVer });
  return gcm(dek, e.nonce, aad).decrypt(e.ciphertext);
}

/** Owner-side decrypt: unwrap DEK with the client KEK, then open. Throws if KEK wrong or shredded. */
export function openCell(e: BlindEnvelope, kek: Uint8Array): Uint8Array {
  const dek = unwrapDek(e, kek);
  try {
    return openCellWithDek(e, dek);
  } finally {
    dek.fill(0);
  }
}
