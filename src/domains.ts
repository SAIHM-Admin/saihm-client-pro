// Canonical SAIHM HKDF domain strings — the subset used CLIENT-SIDE, reused as HKDF `info`.
// Client-side distinctness from SAIHM's own server-seeded identities rests primarily on the
// customer-held input keying material, reinforced by the optional domain-separation tag below.

import { utf8, concat } from './bytes.js';

export const D_PQC_KEY_GEN = 'MPS-PQC-KEY-GEN-v1' as const;
export const D_AGENT_IDENTITY = 'MPS-AGENT-IDENTITY-v1' as const;
export const D_MLKEM_ENCAP = 'MPS-MLKEM-ENCAP-v1' as const;
export const D_KEK = 'MPS-KEK-v1' as const;
export const D_SHARD_NONCE = 'MPS-SHARD-NONCE-v1' as const;

/**
 * Default client/SAIHM domain-separation tag.
 * Appended to HKDF `info` so that even the intermediate seeds cannot collide with any
 * SAIHM-side derivation that reused the same bare domain string. Pass `domainTag: null`
 * to derive with the bare domain string (distinctness then rests on IKM alone).
 */
export const DEFAULT_DOMAIN_TAG = 'saihm-client-crypto-v1' as const;

/** HKDF info = domain || 0x00 || tag  (tag omitted iff `tag === null`). */
export function domainInfo(domain: string, tag: string | null): Uint8Array {
  if (tag === null) return utf8(domain);
  return concat(utf8(domain), new Uint8Array([0]), utf8(tag));
}
