// Blind, authenticated cross-agent sharing. The sharer KEM-encapsulates to the recipient's
// VERIFIED ML-KEM public key and AEAD-wraps the cell DEK under the resulting shared secret
// (KEM-then-AEAD). SAIHM blind-stores the share envelope; it never sees a DEK and cannot
// substitute keys undetected (verifyIdentityRecord pins the recipient out-of-band).

import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ctEqual } from './bytes.js';
import { verifyIdentityRecord } from './identity.js';
import { unwrapDek } from './cell.js';
import { SCHEMA_SHARE, serializeShareForSigning, shareAad } from './wire.js';
import type { BlindEnvelope, IdentityRecord, ShareEnvelope, UnsignedShareEnvelope } from './wire.js';

/** Thrown when a share fails recipient-side authentication (forged/unauthenticated provenance). */
export class ShareAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ShareAuthError';
  }
}

const GCM_NONCE_BYTES = 12;

export interface ShareParams {
  readonly envelope: BlindEnvelope; // the sharer's OWN cell
  readonly sharerKek: Uint8Array;
  readonly sharerMldsaSecretKey: Uint8Array;
  readonly sharerAgentIdHash: Uint8Array;
  readonly recipientRecord: IdentityRecord; // fetched from SAIHM's UNTRUSTED directory
  readonly recipientPinnedAgentIdHash: Uint8Array; // OUT-OF-BAND trusted grantee target
}

export function shareCell(p: ShareParams): ShareEnvelope {
  // Defeats directory key-substitution BEFORE any secret is bound to the recipient key.
  verifyIdentityRecord(p.recipientRecord, p.recipientPinnedAgentIdHash);

  const dek = unwrapDek(p.envelope, p.sharerKek);
  try {
    const { cipherText: kemCipherText, sharedSecret } = ml_kem768.encapsulate(p.recipientRecord.mlkemPubKey);
    try {
      const wrapNonce = randomBytes(GCM_NONCE_BYTES);
      const aad = shareAad({
        sharerAgentIdHash: p.sharerAgentIdHash,
        recipientAgentIdHash: p.recipientPinnedAgentIdHash,
        cellId: p.envelope.cellId,
      });
      const wrappedDek = gcm(sharedSecret, wrapNonce, aad).encrypt(dek);
      const unsigned: UnsignedShareEnvelope = {
        schemaVer: SCHEMA_SHARE,
        cellId: p.envelope.cellId,
        sharerAgentIdHash: p.sharerAgentIdHash,
        recipientAgentIdHash: p.recipientPinnedAgentIdHash,
        kemCipherText,
        wrapNonce,
        wrappedDek,
      };
      const sharerSig = ml_dsa65.sign(serializeShareForSigning(unsigned), p.sharerMldsaSecretKey);
      return { ...unsigned, sharerSig };
    } finally {
      sharedSecret.fill(0);
    }
  } finally {
    dek.fill(0);
  }
}

export interface UnwrapShareParams {
  readonly share: ShareEnvelope;
  readonly recipientMlkemSecretKey: Uint8Array;
  readonly recipientAgentIdHash: Uint8Array; // this agent's own id — the share must name it
  readonly sharerPinnedMldsaPubKey: Uint8Array; // the sharer's OUT-OF-BAND-pinned identity key
}

/**
 * Recipient path — authenticate THEN unwrap, failing closed. The sharer's signature is
 * MANDATORY (the "authenticated sharing" guarantee): a third party who can read the recipient's
 * public ML-KEM key from the untrusted directory could otherwise craft a share that decapsulates
 * for the recipient while falsely claiming another agent as sharer. Verification order:
 *  (1) the share is addressed to this agent;
 *  (2) the claimed `sharerAgentIdHash` matches the out-of-band-pinned sharer public key;
 *  (3) the sharer signature over the whole share verifies;
 * only then (4) KEM-decapsulate + GCM-unwrap.
 */
export function unwrapSharedDek(p: UnwrapShareParams): Uint8Array {
  const { share } = p;
  if (!ctEqual(share.recipientAgentIdHash, p.recipientAgentIdHash)) {
    throw new ShareAuthError('share recipientAgentIdHash does not match this agent');
  }
  if (!ctEqual(sha256(p.sharerPinnedMldsaPubKey), share.sharerAgentIdHash)) {
    throw new ShareAuthError('sharerAgentIdHash does not match the pinned sharer public key');
  }
  if (!ml_dsa65.verify(share.sharerSig, serializeShareForSigning(share), p.sharerPinnedMldsaPubKey)) {
    throw new ShareAuthError('sharer signature invalid (unauthenticated or forged share)');
  }
  const sharedSecret = ml_kem768.decapsulate(share.kemCipherText, p.recipientMlkemSecretKey);
  try {
    return gcm(sharedSecret, share.wrapNonce, shareAad(share)).decrypt(share.wrappedDek);
  } finally {
    sharedSecret.fill(0);
  }
}

/** Standalone sharer-signature check (the same check unwrapSharedDek enforces internally).
 *  Total predicate: a malformed/wrong-length public key or signature returns false, never throws. */
export function verifyShareSig(share: ShareEnvelope, sharerMldsaPubKey: Uint8Array): boolean {
  try {
    return ml_dsa65.verify(share.sharerSig, serializeShareForSigning(share), sharerMldsaPubKey);
  } catch {
    return false;
  }
}
