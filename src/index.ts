// @saihm/client-pro — public surface.
// Client-side envelope cryptography for SAIHM non-custodial memory. Clean-room: built only on
// @noble/* primitives; contains NO SAIHM sealed-core code. The customer master secret, the KEK,
// and plaintext DEKs never leave this library.

export {
  utf8,
  fromUtf8,
  concat,
  concatLP,
  u32be,
  u64be,
  toHex,
  fromHex,
  ctEqual,
} from './bytes.js';

export {
  D_PQC_KEY_GEN,
  D_AGENT_IDENTITY,
  D_MLKEM_ENCAP,
  D_KEK,
  D_SHARD_NONCE,
  DEFAULT_DOMAIN_TAG,
  domainInfo,
} from './domains.js';

export {
  SCHEMA_ENV,
  SCHEMA_SHARE,
  serializePublicMeta,
  serializeForSigning,
  cellAad,
  wrapAad,
  shareAad,
  serializeShareForSigning,
  encodeEnvelope,
  decodeEnvelope,
  encodeShareEnvelope,
  decodeShareEnvelope,
  encodeIdentityRecord,
  decodeIdentityRecord,
  WireFormatError,
} from './wire.js';
export type {
  PublicMeta,
  UnsignedEnvelope,
  BlindEnvelope,
  IdentityRecord,
  UnsignedShareEnvelope,
  ShareEnvelope,
  WirePublicMeta,
  WireEnvelope,
  WireShareEnvelope,
  WireIdentityRecord,
} from './wire.js';

export { deriveIdentity, verifyIdentityRecord, KeySubstitutionError } from './identity.js';
export type { ClientIdentity, DeriveOpts } from './identity.js';

export { sealCell, verifyEnvelope, unwrapDek, openCell, openCellWithDek } from './cell.js';
export type { SealParams } from './cell.js';

export { shareCell, unwrapSharedDek, verifyShareSig, ShareAuthError } from './sharing.js';
export type { ShareParams, UnwrapShareParams } from './sharing.js';

export { acceptSeq, SeqHighWaterMark } from './seq.js';
