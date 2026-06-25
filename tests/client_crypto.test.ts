// @saihm/client-pro — test suite.
// Mandated negative tests + positive round-trips. Run: `npm test` (tsx + node:test).

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import {
  deriveIdentity,
  sealCell,
  verifyEnvelope,
  serializeForSigning,
  openCell,
  openCellWithDek,
  unwrapDek,
  shareCell,
  unwrapSharedDek,
  verifyShareSig,
  verifyIdentityRecord,
  KeySubstitutionError,
  ShareAuthError,
  acceptSeq,
  SeqHighWaterMark,
  encodeEnvelope,
  decodeEnvelope,
  encodeShareEnvelope,
  decodeShareEnvelope,
  encodeIdentityRecord,
  decodeIdentityRecord,
  WireFormatError,
  shareAad,
  serializeShareForSigning,
  SCHEMA_SHARE,
  toHex,
  utf8,
} from '../src/index.js';
import type {
  BlindEnvelope,
  ClientIdentity,
  UnsignedShareEnvelope,
} from '../src/index.js';

const FIXED_NOW = 1_700_000_000_000n;
const PT = utf8('non-custodial encrypted memory cell payload');

function secret(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}
function seal(
  id: ClientIdentity,
  cellId: string,
  seq: bigint,
  pt: Uint8Array = PT,
): BlindEnvelope {
  return sealCell({
    plaintext: pt,
    kek: id.kek,
    mldsaSecretKey: id.mldsaSecretKey,
    mldsaPubKey: id.mldsaPubKey,
    agentIdHash: id.agentIdHash,
    cellId,
    seq,
    tier: 'PRO',
    now: FIXED_NOW,
  });
}

// ─────────────────────────── positives / sanity ────────────────────────────
test('identity derivation is deterministic and matches sha256(mldsaPubKey)', () => {
  const a1 = deriveIdentity(secret(0xa1));
  const a2 = deriveIdentity(secret(0xa1));
  assert.equal(toHex(a1.agentIdHash), toHex(a2.agentIdHash));
  assert.equal(toHex(a1.mldsaPubKey), toHex(a2.mldsaPubKey));
  assert.equal(toHex(a1.kek), toHex(a2.kek));
  assert.equal(a1.agentIdHash.length, 32);
  assert.equal(a1.mldsaPubKey.length, 1952);
  assert.equal(a1.mlkemPubKey.length, 1184);
  // agentIdHash MUST equal sha256(mldsaPubKey) — pins the live bridge JWT `sub`.
  verifyIdentityRecord(a1.identityRecord, a1.agentIdHash); // no throw
});

test('seal -> verify -> open round-trips; envelope field sizes are exact', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-1', 1n);
  assert.equal(verifyEnvelope(env), true);
  assert.deepEqual(openCell(env, a.kek), PT);
  assert.equal(env.nonce.length, 12);
  assert.equal(env.wrappedDek.length, 60); // 12 wrapNonce + 32 dek + 16 tag
  assert.equal(env.mldsaSig.length, 3309);
  assert.equal(toHex(env.publicMeta.commitmentHash).length, 64);
});

test('wire encode/decode is loss-free and preserves verifiability', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-w', 7n);
  const decoded = decodeEnvelope(encodeEnvelope(env));
  assert.equal(verifyEnvelope(decoded), true);
  assert.equal(decoded.seq, 7n);
  assert.deepEqual(openCell(decoded, a.kek), PT);
});

// ─────────────────── NT1: SAIHM cannot decrypt (blind) ──────────────────────
test('NT1: SAIHM holds the envelope but cannot recover plaintext without the client KEK', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-1', 1n);
  // SAIHM CAN verify (it has the public key + signature)…
  assert.equal(verifyEnvelope(env), true);
  // …but with no KEK it cannot unwrap the DEK nor open the cell.
  const notTheKek = randomBytes(32);
  assert.throws(() => unwrapDek(env, notTheKek));
  assert.throws(() => openCell(env, notTheKek));
  // Nor can it brute a DEK: a random/guessed DEK fails the GCM tag.
  assert.throws(() => openCellWithDek(env, randomBytes(32)));
});

// ─────────────────── NT2: cross-tenant isolation ───────────────────────────
test('NT2: tenant B cannot read tenant A (distinct namespace + KEK)', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  assert.notEqual(toHex(a.agentIdHash), toHex(b.agentIdHash));
  assert.notEqual(toHex(a.kek), toHex(b.kek));
  const envA = seal(a, 'cell-1', 1n);
  assert.deepEqual(openCell(envA, a.kek), PT); // owner OK
  assert.throws(() => openCell(envA, b.kek)); // B's KEK cannot unwrap A's wDEK
  assert.throws(() => unwrapDek(envA, b.kek));
});

// ─────────────────── NT3: share key-substitution + cross-tenant decrypt ─────
test('NT3a: genuine authenticated share lets B decrypt A’s cell cross-tenant', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  const envA = seal(a, 'cell-shared', 1n);
  const share = shareCell({
    envelope: envA,
    sharerKek: a.kek,
    sharerMldsaSecretKey: a.mldsaSecretKey,
    sharerAgentIdHash: a.agentIdHash,
    recipientRecord: b.identityRecord,
    recipientPinnedAgentIdHash: b.agentIdHash,
  });
  assert.equal(verifyShareSig(share, a.mldsaPubKey), true);
  const dek = unwrapSharedDek({
    share,
    recipientMlkemSecretKey: b.mlkemSecretKey,
    recipientAgentIdHash: b.agentIdHash,
    sharerPinnedMldsaPubKey: a.mldsaPubKey,
  });
  assert.deepEqual(openCellWithDek(envA, dek), PT);
});

test('NT3b: substituted recipient DSA key is rejected (hash != pinned target)', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  const evil = deriveIdentity(secret(0xee));
  const envA = seal(a, 'cell-shared', 1n);
  // Directory returns evil's DSA key but claims to be B.
  const tampered = {
    mldsaPubKey: evil.mldsaPubKey,
    mlkemPubKey: b.mlkemPubKey,
    mlkemPubKeySelfSig: b.identityRecord.mlkemPubKeySelfSig,
  };
  assert.throws(
    () =>
      shareCell({
        envelope: envA,
        sharerKek: a.kek,
        sharerMldsaSecretKey: a.mldsaSecretKey,
        sharerAgentIdHash: a.agentIdHash,
        recipientRecord: tampered,
        recipientPinnedAgentIdHash: b.agentIdHash, // out-of-band-pinned true B
      }),
    KeySubstitutionError,
  );
});

test('NT3c: substituted recipient KEM key (genuine DSA) is rejected by the self-sig', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  const evil = deriveIdentity(secret(0xee));
  const envA = seal(a, 'cell-shared', 1n);
  // Keep B's DSA identity (so the hash check passes) but swap in evil's KEM key.
  const tampered = {
    mldsaPubKey: b.mldsaPubKey,
    mlkemPubKey: evil.mlkemPubKey,
    mlkemPubKeySelfSig: b.identityRecord.mlkemPubKeySelfSig, // signs B's KEM key, not evil's
  };
  assert.throws(
    () =>
      shareCell({
        envelope: envA,
        sharerKek: a.kek,
        sharerMldsaSecretKey: a.mldsaSecretKey,
        sharerAgentIdHash: a.agentIdHash,
        recipientRecord: tampered,
        recipientPinnedAgentIdHash: b.agentIdHash,
      }),
    KeySubstitutionError,
  );
});

// ─────────────────── NT4: wrapped-DEK crypto-shred erasure ──────────────────
test('NT4: destroying the SAIHM-side wrappedDek renders the cell undecryptable (Art.17)', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-forget', 1n);
  assert.deepEqual(openCell(env, a.kek), PT); // control: openable while wDEK exists
  // `forget` = SAIHM destroys the wrappedDek store entry. Model as a zeroed/absent entry.
  const shredded: BlindEnvelope = {
    ...env,
    wrappedDek: new Uint8Array(env.wrappedDek.length),
  };
  // Even WITH the correct client KEK, the random DEK is gone — nothing can reconstruct it.
  assert.throws(() => unwrapDek(shredded, a.kek));
  assert.throws(() => openCell(shredded, a.kek));
});

// ─────────────────── NT5: replay / rollback (stale seq) rejection ───────────
test('NT5: monotonic seq rejects replay/rollback, and the signature binds seq', () => {
  const a = deriveIdentity(secret(0xa1));
  const idHex = toHex(a.agentIdHash);
  const hw = new SeqHighWaterMark();
  assert.equal(hw.admit(idHex, 'c', 1n), true); // first write
  assert.equal(hw.admit(idHex, 'c', 1n), false); // replay rejected
  assert.equal(hw.admit(idHex, 'c', 0n), false); // rollback rejected
  assert.equal(hw.admit(idHex, 'c', 2n), true); // advance accepted
  assert.equal(acceptSeq(5n, 4n), false);
  assert.equal(acceptSeq(undefined, 0n), true);

  // The signature covers seq: an attacker rolling seq back invalidates the signature.
  const env = seal(a, 'c', 5n);
  const rolledBack: BlindEnvelope = { ...env, seq: 4n };
  assert.equal(verifyEnvelope(rolledBack), false);
});

// ─── NT6: anchor soundness — commitmentHash must commit to the stored ciphertext ───
test('NT6: a validly-signed envelope whose commitmentHash lies about the ciphertext is rejected', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-commit', 1n);
  assert.equal(verifyEnvelope(env), true); // honest control
  // Forge: keep the ciphertext, set a wrong commitmentHash, and RE-SIGN with the real key.
  const lying = {
    ...env,
    publicMeta: { ...env.publicMeta, commitmentHash: new Uint8Array(32) },
  };
  const mldsaSig = ml_dsa65.sign(serializeForSigning(lying), a.mldsaSecretKey);
  const signedLie: BlindEnvelope = { ...lying, mldsaSig };
  // The signature is valid over the lie, but verifyEnvelope binds commitmentHash to the ciphertext.
  assert.equal(verifyEnvelope(signedLie), false);
});

// ─── NT7: recipient-side sharer authentication is mandatory (forged provenance rejected) ───
test('NT7: a share falsely claiming another agent as sharer is rejected (fail closed)', () => {
  const a = deriveIdentity(secret(0xa1)); // the agent E will try to impersonate
  const b = deriveIdentity(secret(0xb2)); // the recipient
  const evil = deriveIdentity(secret(0xee)); // attacker E (cannot sign as A)
  // E crafts a share that decapsulates for B but claims sharerAgentIdHash = A.
  const evilDek = randomBytes(32);
  const { cipherText: kemCipherText, sharedSecret } = ml_kem768.encapsulate(
    b.mlkemPubKey,
  );
  const wrapNonce = randomBytes(12);
  const aad = shareAad({
    sharerAgentIdHash: a.agentIdHash,
    recipientAgentIdHash: b.agentIdHash,
    cellId: 'x',
  });
  const wrappedDek = gcm(sharedSecret, wrapNonce, aad).encrypt(evilDek);
  const unsigned: UnsignedShareEnvelope = {
    schemaVer: SCHEMA_SHARE,
    cellId: 'x',
    sharerAgentIdHash: a.agentIdHash,
    recipientAgentIdHash: b.agentIdHash,
    kemCipherText,
    wrapNonce,
    wrappedDek,
  };
  // E can only sign with E's own key — it does not hold A's secret key.
  const forged = {
    ...unsigned,
    sharerSig: ml_dsa65.sign(
      serializeShareForSigning(unsigned),
      evil.mldsaSecretKey,
    ),
  };
  assert.throws(
    () =>
      unwrapSharedDek({
        share: forged,
        recipientMlkemSecretKey: b.mlkemSecretKey,
        recipientAgentIdHash: b.agentIdHash,
        sharerPinnedMldsaPubKey: a.mldsaPubKey, // B pins the true A out-of-band
      }),
    ShareAuthError,
  );
});

// ─── NT8: malformed wire input is rejected without throwing on the verify gate (DoS-safe) ───
test('NT8: out-of-range seq/createdAt are rejected at decode, and verifyEnvelope fails closed', () => {
  const a = deriveIdentity(secret(0xa1));
  const env = seal(a, 'cell-dos', 1n);
  const w = encodeEnvelope(env);
  // decodeEnvelope rejects out-of-uint64 / negative / non-integer seq + createdAt as malformed wire.
  assert.throws(() => decodeEnvelope({ ...w, seq: '-1' }), WireFormatError);
  assert.throws(
    () => decodeEnvelope({ ...w, seq: (2n ** 64n).toString() }),
    WireFormatError,
  );
  assert.throws(
    () => decodeEnvelope({ ...w, seq: 'not-a-number' }),
    WireFormatError,
  );
  assert.throws(
    () =>
      decodeEnvelope({
        ...w,
        publicMeta: { ...w.publicMeta, createdAt: '-1' },
      }),
    WireFormatError,
  );
  // Defense in depth: even a directly-constructed envelope with an out-of-range seq makes the
  // blind server's verify gate return false — it MUST NOT throw (no unhandled-exception DoS).
  const oob: BlindEnvelope = { ...env, seq: -1n };
  let threw = false;
  let result = true;
  try {
    result = verifyEnvelope(oob);
  } catch {
    threw = true;
  }
  assert.equal(threw, false); // never throws
  assert.equal(result, false); // fails closed
});

// ─── NT9: byte-field hex transport is strictly canonical (no malformed/malleable decode) ───
test('NT9: malformed / non-canonical hex byte-fields are rejected at decode with WireFormatError', () => {
  const a = deriveIdentity(secret(0xa1));
  const w = encodeEnvelope(seal(a, 'cell-hex', 1n));
  // Each hex byte-field must reject odd-length, non-hex, uppercase, whitespace, sign, and 0x forms
  // as malformed wire — a single typed WireFormatError at the parse boundary, never an untyped throw.
  for (const bad of ['abc', 'zz', '1g', 'AB', ' a', '-1', '0x01']) {
    assert.throws(
      () => decodeEnvelope({ ...w, agentIdHash: bad }),
      WireFormatError,
    );
    assert.throws(
      () => decodeEnvelope({ ...w, ciphertext: bad }),
      WireFormatError,
    );
    assert.throws(() => decodeEnvelope({ ...w, nonce: bad }), WireFormatError);
    assert.throws(
      () => decodeEnvelope({ ...w, wrappedDek: bad }),
      WireFormatError,
    );
    assert.throws(
      () => decodeEnvelope({ ...w, mldsaPubKey: bad }),
      WireFormatError,
    );
    assert.throws(
      () => decodeEnvelope({ ...w, mldsaSig: bad }),
      WireFormatError,
    );
    assert.throws(
      () =>
        decodeEnvelope({
          ...w,
          publicMeta: { ...w.publicMeta, commitmentHash: bad },
        }),
      WireFormatError,
    );
  }
  // Fixed-size byte fields reject valid-hex-but-WRONG-LENGTH input at decode (ahead of the signature).
  assert.throws(
    () => decodeEnvelope({ ...w, agentIdHash: 'aa' }),
    WireFormatError,
  );
  assert.throws(() => decodeEnvelope({ ...w, nonce: 'aabb' }), WireFormatError);
  assert.throws(
    () => decodeEnvelope({ ...w, mldsaPubKey: 'aabbcc' }),
    WireFormatError,
  );
  // The honest, canonical encoding still round-trips and verifies.
  assert.equal(verifyEnvelope(decodeEnvelope(w)), true);
});

// ─── NT10: standalone helpers are robust (total verifyShareSig; DEK-length-checked open) ───
test('NT10: verifyShareSig fails closed on a malformed pubkey; openCellWithDek rejects a non-32B DEK', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  const envA = seal(a, 'cell-robust', 1n);
  const share = shareCell({
    envelope: envA,
    sharerKek: a.kek,
    sharerMldsaSecretKey: a.mldsaSecretKey,
    sharerAgentIdHash: a.agentIdHash,
    recipientRecord: b.identityRecord,
    recipientPinnedAgentIdHash: b.agentIdHash,
  });
  // verifyShareSig is a total predicate: a wrong-length sharer pubkey returns false, never throws.
  let threw = false;
  let res = true;
  try {
    res = verifyShareSig(share, new Uint8Array(10));
  } catch {
    threw = true;
  }
  assert.equal(threw, false);
  assert.equal(res, false);
  assert.equal(verifyShareSig(share, a.mldsaPubKey), true); // genuine pubkey still verifies (control)
  // openCellWithDek rejects a short DEK before any GCM call (no silent AES-128/192 downgrade).
  assert.throws(
    () => openCellWithDek(envA, new Uint8Array(16)),
    /dek must be 32 bytes/,
  );
});

// ─── NT11: structural / wrong-type wire is rejected with WireFormatError (no untyped TypeError) ───
test('NT11: null/absent publicMeta, a null body, and non-string fields are rejected with WireFormatError', () => {
  const a = deriveIdentity(secret(0xa1));
  const w = encodeEnvelope(seal(a, 'cell-struct', 1n));
  // Structural malformation must surface as the single typed WireFormatError — the blind server
  // wraps decode and treats WireFormatError as a 4xx reject; an untyped TypeError would be a 500/DoS.
  assert.throws(
    () => decodeEnvelope({ ...w, publicMeta: null as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeEnvelope({ ...w, publicMeta: undefined as any }),
    WireFormatError,
  );
  assert.throws(() => decodeEnvelope(null as any), WireFormatError);
  // Wrong JSON type (number / object where a string is required) is rejected, not coerced.
  assert.throws(
    () => decodeEnvelope({ ...w, schemaVer: 123 as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeEnvelope({ ...w, cellId: 123 as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeEnvelope({ ...w, agentIdHash: 0 as any }),
    WireFormatError,
  );
  // JSON numbers for integer fields are rejected (incl. >=2^53 — no silent precision loss).
  assert.throws(() => decodeEnvelope({ ...w, seq: 1 as any }), WireFormatError);
  assert.throws(
    () => decodeEnvelope({ ...w, seq: (2 ** 53 + 1) as any }),
    WireFormatError,
  );
  assert.throws(
    () =>
      decodeEnvelope({
        ...w,
        publicMeta: { ...w.publicMeta, createdAt: 5 as any },
      }),
    WireFormatError,
  );
  // Honest, well-typed wire still round-trips and verifies.
  assert.equal(verifyEnvelope(decodeEnvelope(w)), true);
});

// ─── NT12: share-envelope JSON transport — canonical, totally validated, round-trips ───
test('NT12: share envelope encode/decode round-trips and rejects malformed/wrong-length wire with WireFormatError', () => {
  const a = deriveIdentity(secret(0xa1));
  const b = deriveIdentity(secret(0xb2));
  const envA = seal(a, 'cell-share-wire', 1n);
  const share = shareCell({
    envelope: envA,
    sharerKek: a.kek,
    sharerMldsaSecretKey: a.mldsaSecretKey,
    sharerAgentIdHash: a.agentIdHash,
    recipientRecord: b.identityRecord,
    recipientPinnedAgentIdHash: b.agentIdHash,
  });
  const w = encodeShareEnvelope(share);
  // Round-trip preserves the share so the recipient can still authenticate + unwrap it.
  const dek = unwrapSharedDek({
    share: decodeShareEnvelope(w),
    recipientMlkemSecretKey: b.mlkemSecretKey,
    recipientAgentIdHash: b.agentIdHash,
    sharerPinnedMldsaPubKey: a.mldsaPubKey,
  });
  assert.deepEqual(openCellWithDek(envA, dek), PT);
  // The blind server keys its share-store on these fields, so malformed share JSON must surface a
  // single typed WireFormatError, never an untyped throw.
  assert.throws(() => decodeShareEnvelope(null as any), WireFormatError);
  assert.throws(
    () => decodeShareEnvelope({ ...w, sharerAgentIdHash: null as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeShareEnvelope({ ...w, cellId: 123 as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeShareEnvelope({ ...w, kemCipherText: 'zz' }),
    WireFormatError,
  ); // non-hex
  assert.throws(
    () => decodeShareEnvelope({ ...w, kemCipherText: 'aa' }),
    WireFormatError,
  ); // wrong length
  assert.throws(
    () => decodeShareEnvelope({ ...w, sharerSig: w.sharerSig.toUpperCase() }),
    WireFormatError,
  ); // uppercase
});

// ─── NT13: identity-record JSON transport — canonical, totally validated, round-trips ───
test('NT13: identity record encode/decode round-trips and rejects malformed/wrong-length wire with WireFormatError', () => {
  const a = deriveIdentity(secret(0xa1));
  const w = encodeIdentityRecord(a.identityRecord);
  const decoded = decodeIdentityRecord(w);
  // Round-trip preserves the record so out-of-band pinning still verifies it.
  verifyIdentityRecord(decoded, a.agentIdHash); // no throw
  assert.equal(toHex(decoded.mldsaPubKey), toHex(a.identityRecord.mldsaPubKey));
  // Malformed directory JSON must surface a single typed WireFormatError, never an untyped throw.
  assert.throws(() => decodeIdentityRecord(null as any), WireFormatError);
  assert.throws(
    () => decodeIdentityRecord({ ...w, mldsaPubKey: 5 as any }),
    WireFormatError,
  );
  assert.throws(
    () => decodeIdentityRecord({ ...w, mlkemPubKey: 'zz' }),
    WireFormatError,
  ); // non-hex
  assert.throws(
    () => decodeIdentityRecord({ ...w, mlkemPubKey: 'aa' }),
    WireFormatError,
  ); // wrong length
  assert.throws(
    () =>
      decodeIdentityRecord({
        ...w,
        mlkemPubKeySelfSig: w.mlkemPubKeySelfSig.toUpperCase(),
      }),
    WireFormatError,
  );
});
