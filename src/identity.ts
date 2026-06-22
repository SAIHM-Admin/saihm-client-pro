// Client-side identity derivation. The customer's master secret, the derived KEK, and the
// ML-DSA/ML-KEM secret keys NEVER leave the client. Only the IdentityRecord (public keys +
// self-signature) and the agentIdHash are published to SAIHM.

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ctEqual } from './bytes.js';
import {
  domainInfo,
  DEFAULT_DOMAIN_TAG,
  D_PQC_KEY_GEN,
  D_AGENT_IDENTITY,
  D_MLKEM_ENCAP,
  D_KEK,
} from './domains.js';
import type { IdentityRecord } from './wire.js';

export interface ClientIdentity {
  readonly mldsaSecretKey: Uint8Array;
  readonly mldsaPubKey: Uint8Array;
  readonly mlkemSecretKey: Uint8Array;
  readonly mlkemPubKey: Uint8Array;
  readonly kek: Uint8Array; // 32 — wraps per-cell DEKs; NEVER leaves the client
  readonly agentIdHash: Uint8Array; // 32 = sha256(mldsaPubKey) = JWT sub
  readonly identityRecord: IdentityRecord;
}

export interface DeriveOpts {
  /** Domain-separation tag. `undefined` => default; `null` => bare domain string. */
  readonly domainTag?: string | null;
}

/**
 * Derive a full client identity from a master secret (>= 32 bytes of high-entropy material).
 * Deterministic: same secret (+ tag) => same identity, on any device.
 *
 * Seed derivation (seed-then-keygen; the HKDF domains yield SEEDS, @noble does keygen):
 *   kgRoot     = HKDF(ikm=masterSecret, info=MPS-PQC-KEY-GEN-v1)
 *   mldsaSeed  = HKDF(ikm=kgRoot,       info=MPS-AGENT-IDENTITY-v1, 32B)
 *   mlkemSeed  = HKDF(ikm=kgRoot,       info=MPS-MLKEM-ENCAP-v1,    64B)
 *   kek        = HKDF(ikm=masterSecret, info=MPS-KEK-v1,            32B)
 */
export function deriveIdentity(masterSecret: Uint8Array, opts: DeriveOpts = {}): ClientIdentity {
  if (masterSecret.length < 32) {
    throw new Error('masterSecret must be >= 32 bytes of high-entropy material');
  }
  const tag = opts.domainTag === undefined ? DEFAULT_DOMAIN_TAG : opts.domainTag;

  const kgRoot = hkdf(sha256, masterSecret, undefined, domainInfo(D_PQC_KEY_GEN, tag), 32);
  const mldsaSeed = hkdf(sha256, kgRoot, undefined, domainInfo(D_AGENT_IDENTITY, tag), 32);
  const mlkemSeed = hkdf(sha256, kgRoot, undefined, domainInfo(D_MLKEM_ENCAP, tag), 64);
  const kek = hkdf(sha256, masterSecret, undefined, domainInfo(D_KEK, tag), 32);

  const dsa = ml_dsa65.keygen(mldsaSeed);
  const kem = ml_kem768.keygen(mlkemSeed);
  const agentIdHash = sha256(dsa.publicKey);
  const mlkemPubKeySelfSig = ml_dsa65.sign(kem.publicKey, dsa.secretKey);

  kgRoot.fill(0);
  mldsaSeed.fill(0);
  mlkemSeed.fill(0);

  return {
    mldsaSecretKey: dsa.secretKey,
    mldsaPubKey: dsa.publicKey,
    mlkemSecretKey: kem.secretKey,
    mlkemPubKey: kem.publicKey,
    kek,
    agentIdHash,
    identityRecord: {
      mldsaPubKey: dsa.publicKey,
      mlkemPubKey: kem.publicKey,
      mlkemPubKeySelfSig,
    },
  };
}

export class KeySubstitutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeySubstitutionError';
  }
}

/**
 * Verify a directory-fetched recipient record against an OUT-OF-BAND-pinned agentIdHash.
 *  (a) sha256(mldsaPubKey) MUST equal the pinned target — defeats DSA-key substitution;
 *  (b) the self-signature MUST bind mlkemPubKey to that DSA key — defeats KEM-key substitution.
 * The self-sig ALONE proves only internal consistency; both checks are required.
 */
export function verifyIdentityRecord(record: IdentityRecord, pinnedAgentIdHash: Uint8Array): void {
  if (!ctEqual(sha256(record.mldsaPubKey), pinnedAgentIdHash)) {
    throw new KeySubstitutionError(
      'mldsaPubKey does not hash to the pinned agentIdHash (directory key substitution)',
    );
  }
  if (!ml_dsa65.verify(record.mlkemPubKeySelfSig, record.mlkemPubKey, record.mldsaPubKey)) {
    throw new KeySubstitutionError('mlkemPubKey self-signature invalid (substituted KEM key)');
  }
}
