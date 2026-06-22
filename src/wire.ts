// Blind-envelope wire format + identity record + share envelope — the client<->core contract.
// SAIHM stores/verifies these but holds NO key able to decrypt `ciphertext` or unwrap `wrappedDek`.
// Byte-exact canonical serialization (length-prefixed) is the core of this contract.

import { concatLP, utf8, u64be, toHex, fromHex } from './bytes.js';

export const SCHEMA_ENV = 'saihm-blind-env/1' as const;
export const SCHEMA_SHARE = 'saihm-share-env/1' as const;

// ── Public metadata (no plaintext; safe for SAIHM to read/anchor) ─────────────
export interface PublicMeta {
  readonly tier: string; // billing tier asserted by the JWT at write time
  readonly createdAt: bigint; // unix ms
  readonly commitmentHash: Uint8Array; // 32 = sha256(ciphertext) — anchorable
}

export function serializePublicMeta(m: PublicMeta): Uint8Array {
  return concatLP(utf8(m.tier), u64be(m.createdAt), m.commitmentHash);
}

// ── Blind envelope ────────────────────────────────────────────────────────────
export interface UnsignedEnvelope {
  readonly schemaVer: string;
  readonly agentIdHash: Uint8Array; // 32 = sha256(mldsaPubKey) = JWT sub
  readonly cellId: string;
  readonly seq: bigint; // server-issued monotonic per-cell counter
  readonly ciphertext: Uint8Array; // AES-256-GCM(dek, nonce, cellAad) incl. 16B tag
  readonly nonce: Uint8Array; // 12
  readonly wrappedDek: Uint8Array; // wrapNonce(12) || AES-256-GCM(kek)(dek) => 60
  readonly mldsaPubKey: Uint8Array; // 1952
  readonly publicMeta: PublicMeta;
}
export interface BlindEnvelope extends UnsignedEnvelope {
  readonly mldsaSig: Uint8Array; // 3309 = ML-DSA-65(mldsaSk, serializeForSigning(unsigned))
}

/** Canonical signed-message bytes — every field EXCEPT mldsaSig, length-prefixed, fixed order. */
export function serializeForSigning(e: UnsignedEnvelope): Uint8Array {
  return concatLP(
    utf8(e.schemaVer),
    e.agentIdHash,
    utf8(e.cellId),
    u64be(e.seq),
    e.ciphertext,
    e.nonce,
    e.wrappedDek,
    e.mldsaPubKey,
    serializePublicMeta(e.publicMeta),
  );
}

/** AAD binding the plaintext ciphertext to (agent, cell, seq, schema). */
export function cellAad(e: {
  agentIdHash: Uint8Array;
  cellId: string;
  seq: bigint;
  schemaVer: string;
}): Uint8Array {
  return concatLP(e.agentIdHash, utf8(e.cellId), u64be(e.seq), utf8(e.schemaVer));
}

/** AAD binding a wrapped DEK to (agent, cell, seq, schema). */
export function wrapAad(e: {
  agentIdHash: Uint8Array;
  cellId: string;
  seq: bigint;
  schemaVer: string;
}): Uint8Array {
  return concatLP(e.agentIdHash, utf8(e.cellId), u64be(e.seq), utf8(e.schemaVer));
}

// ── Identity record (published to SAIHM's untrusted directory) ─────────────────
export interface IdentityRecord {
  readonly mldsaPubKey: Uint8Array; // 1952
  readonly mlkemPubKey: Uint8Array; // 1184
  readonly mlkemPubKeySelfSig: Uint8Array; // 3309 = ML-DSA-65(mldsaSk, mlkemPubKey)
}

// ── Share envelope (client ML-KEM-wrapped DEK; SAIHM blind-stores it) ──────────
export interface UnsignedShareEnvelope {
  readonly schemaVer: string;
  readonly cellId: string;
  readonly sharerAgentIdHash: Uint8Array; // 32
  readonly recipientAgentIdHash: Uint8Array; // 32 (out-of-band-pinned target)
  readonly kemCipherText: Uint8Array; // 1088 = ML-KEM-768 encapsulation
  readonly wrapNonce: Uint8Array; // 12
  readonly wrappedDek: Uint8Array; // 48 = AES-256-GCM(sharedSecret)(dek)
}
export interface ShareEnvelope extends UnsignedShareEnvelope {
  readonly sharerSig: Uint8Array; // 3309 = ML-DSA-65(sharerSk, serializeShareForSigning)
}

export function shareAad(s: {
  sharerAgentIdHash: Uint8Array;
  recipientAgentIdHash: Uint8Array;
  cellId: string;
}): Uint8Array {
  return concatLP(s.sharerAgentIdHash, s.recipientAgentIdHash, utf8(s.cellId));
}

export function serializeShareForSigning(s: UnsignedShareEnvelope): Uint8Array {
  return concatLP(
    utf8(s.schemaVer),
    utf8(s.cellId),
    s.sharerAgentIdHash,
    s.recipientAgentIdHash,
    s.kemCipherText,
    s.wrapNonce,
    s.wrappedDek,
  );
}

// ── JSON-safe transport encoding (hex for bytes, decimal string for bigint) ────
export interface WirePublicMeta {
  readonly tier: string;
  readonly createdAt: string;
  readonly commitmentHash: string;
}
export interface WireEnvelope {
  readonly schemaVer: string;
  readonly agentIdHash: string;
  readonly cellId: string;
  readonly seq: string;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly wrappedDek: string;
  readonly mldsaPubKey: string;
  readonly mldsaSig: string;
  readonly publicMeta: WirePublicMeta;
}

export function encodeEnvelope(e: BlindEnvelope): WireEnvelope {
  return {
    schemaVer: e.schemaVer,
    agentIdHash: toHex(e.agentIdHash),
    cellId: e.cellId,
    seq: e.seq.toString(10),
    ciphertext: toHex(e.ciphertext),
    nonce: toHex(e.nonce),
    wrappedDek: toHex(e.wrappedDek),
    mldsaPubKey: toHex(e.mldsaPubKey),
    mldsaSig: toHex(e.mldsaSig),
    publicMeta: {
      tier: e.publicMeta.tier,
      createdAt: e.publicMeta.createdAt.toString(10),
      commitmentHash: toHex(e.publicMeta.commitmentHash),
    },
  };
}

/** Thrown when transport JSON is structurally invalid (e.g. an out-of-range integer field). */
export class WireFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WireFormatError';
  }
}

const U64_MAX = 0xffffffffffffffffn;
const CANONICAL_U64 = /^(?:0|[1-9][0-9]*)$/; // canonical decimal: no sign, no leading zero, no 0x/0o/0b

// Canonical fixed field sizes in bytes (FIPS-204 ML-DSA-65, FIPS-203 ML-KEM-768, SHA-256,
// AES-256-GCM). Decoders length-check fixed hex fields; variable fields (ciphertext) are exempt.
const LEN_HASH = 32; // sha256: agentIdHash / commitmentHash
const LEN_GCM_NONCE = 12;
const LEN_MLDSA_PUB = 1952;
const LEN_MLDSA_SIG = 3309;
const LEN_MLKEM_PUB = 1184;
const LEN_MLKEM_CT = 1088;
const LEN_WRAPPED_DEK_CELL = 60; // 12 nonce + 32 dek + 16 tag
const LEN_WRAPPED_DEK_SHARE = 48; // 32 dek + 16 tag

/** Parse a canonical decimal-string uint64; reject any non-canonical or out-of-range value as malformed wire. */
function parseU64(s: string, field: string): bigint {
  if (typeof s !== 'string') throw new WireFormatError(`${field} must be a decimal string`);
  if (!CANONICAL_U64.test(s)) throw new WireFormatError(`${field} is not a canonical decimal uint64`);
  const v = BigInt(s);
  if (v > U64_MAX) throw new WireFormatError(`${field} out of uint64 range`);
  return v;
}

/** Decode a canonical lowercase-hex wire field, surfacing any malformation as WireFormatError
 *  (so the blind server's decode boundary throws ONE typed error class, never an untyped Error). */
function hexField(s: string, field: string, expectedLen?: number): Uint8Array {
  if (typeof s !== 'string') throw new WireFormatError(`${field} must be a lowercase-hex string`);
  let bytes: Uint8Array;
  try {
    bytes = fromHex(s);
  } catch {
    throw new WireFormatError(`${field} is not canonical lowercase hex`);
  }
  if (expectedLen !== undefined && bytes.length !== expectedLen) {
    throw new WireFormatError(`${field} must be ${expectedLen} bytes`);
  }
  return bytes;
}

/** Pass-through string wire field — validated to be a string (the JSON wire type); content is
 *  not constrained (its integrity rests on the signature), but a non-string is malformed wire. */
function strField(s: string, field: string): string {
  if (typeof s !== 'string') throw new WireFormatError(`${field} must be a string`);
  return s;
}

export function decodeEnvelope(w: WireEnvelope): BlindEnvelope {
  // TOTAL over UNTRUSTED input: every field is validated to its JSON wire type and canonical form,
  // and the whole body is wrapped so STRUCTURAL malformation (e.g. a null/absent publicMeta or a
  // non-object body) surfaces as the SAME typed WireFormatError — never an untyped TypeError. The
  // blind server treats WireFormatError as a 4xx reject; with the total-predicate verifyEnvelope
  // this leaves no unhandled-exception / DoS surface on the decode->verify path.
  try {
    return {
      schemaVer: strField(w.schemaVer, 'schemaVer'),
      agentIdHash: hexField(w.agentIdHash, 'agentIdHash', LEN_HASH),
      cellId: strField(w.cellId, 'cellId'),
      seq: parseU64(w.seq, 'seq'),
      ciphertext: hexField(w.ciphertext, 'ciphertext'),
      nonce: hexField(w.nonce, 'nonce', LEN_GCM_NONCE),
      wrappedDek: hexField(w.wrappedDek, 'wrappedDek', LEN_WRAPPED_DEK_CELL),
      mldsaPubKey: hexField(w.mldsaPubKey, 'mldsaPubKey', LEN_MLDSA_PUB),
      mldsaSig: hexField(w.mldsaSig, 'mldsaSig', LEN_MLDSA_SIG),
      publicMeta: {
        tier: strField(w.publicMeta.tier, 'tier'),
        createdAt: parseU64(w.publicMeta.createdAt, 'createdAt'),
        commitmentHash: hexField(w.publicMeta.commitmentHash, 'commitmentHash', LEN_HASH),
      },
    };
  } catch (e) {
    if (e instanceof WireFormatError) throw e;
    throw new WireFormatError('malformed envelope structure');
  }
}

// ── Identity-record JSON transport (published to SAIHM's UNTRUSTED directory) ──────────────────
export interface WireIdentityRecord {
  readonly mldsaPubKey: string;
  readonly mlkemPubKey: string;
  readonly mlkemPubKeySelfSig: string;
}

export function encodeIdentityRecord(r: IdentityRecord): WireIdentityRecord {
  return {
    mldsaPubKey: toHex(r.mldsaPubKey),
    mlkemPubKey: toHex(r.mlkemPubKey),
    mlkemPubKeySelfSig: toHex(r.mlkemPubKeySelfSig),
  };
}

/** TOTAL over UNTRUSTED directory input — like decodeEnvelope, every field is canonical lowercase
 *  hex of its exact fixed length, and any malformation surfaces as a single typed WireFormatError. */
export function decodeIdentityRecord(w: WireIdentityRecord): IdentityRecord {
  try {
    return {
      mldsaPubKey: hexField(w.mldsaPubKey, 'mldsaPubKey', LEN_MLDSA_PUB),
      mlkemPubKey: hexField(w.mlkemPubKey, 'mlkemPubKey', LEN_MLKEM_PUB),
      mlkemPubKeySelfSig: hexField(w.mlkemPubKeySelfSig, 'mlkemPubKeySelfSig', LEN_MLDSA_SIG),
    };
  } catch (e) {
    if (e instanceof WireFormatError) throw e;
    throw new WireFormatError('malformed identity record structure');
  }
}

// ── Share-envelope JSON transport (client ML-KEM share; SAIHM append-stores it BLIND) ──────────
export interface WireShareEnvelope {
  readonly schemaVer: string;
  readonly cellId: string;
  readonly sharerAgentIdHash: string;
  readonly recipientAgentIdHash: string;
  readonly kemCipherText: string;
  readonly wrapNonce: string;
  readonly wrappedDek: string;
  readonly sharerSig: string;
}

export function encodeShareEnvelope(s: ShareEnvelope): WireShareEnvelope {
  return {
    schemaVer: s.schemaVer,
    cellId: s.cellId,
    sharerAgentIdHash: toHex(s.sharerAgentIdHash),
    recipientAgentIdHash: toHex(s.recipientAgentIdHash),
    kemCipherText: toHex(s.kemCipherText),
    wrapNonce: toHex(s.wrapNonce),
    wrappedDek: toHex(s.wrappedDek),
    sharerSig: toHex(s.sharerSig),
  };
}

/** TOTAL over UNTRUSTED input — the SAIHM runtime keys its blind share-store on
 *  (agentIdHash, cellId, recipientAgentIdHash) (owner-namespaced), so it parses this envelope;
 *  like decodeEnvelope it surfaces all malformation (structural, wrong-type,
 *  non-canonical/wrong-length hex) as one WireFormatError. */
export function decodeShareEnvelope(w: WireShareEnvelope): ShareEnvelope {
  try {
    return {
      schemaVer: strField(w.schemaVer, 'schemaVer'),
      cellId: strField(w.cellId, 'cellId'),
      sharerAgentIdHash: hexField(w.sharerAgentIdHash, 'sharerAgentIdHash', LEN_HASH),
      recipientAgentIdHash: hexField(w.recipientAgentIdHash, 'recipientAgentIdHash', LEN_HASH),
      kemCipherText: hexField(w.kemCipherText, 'kemCipherText', LEN_MLKEM_CT),
      wrapNonce: hexField(w.wrapNonce, 'wrapNonce', LEN_GCM_NONCE),
      wrappedDek: hexField(w.wrappedDek, 'wrappedDek', LEN_WRAPPED_DEK_SHARE),
      sharerSig: hexField(w.sharerSig, 'sharerSig', LEN_MLDSA_SIG),
    };
  } catch (e) {
    if (e instanceof WireFormatError) throw e;
    throw new WireFormatError('malformed share envelope structure');
  }
}
