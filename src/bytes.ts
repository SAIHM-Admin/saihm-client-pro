// Low-level byte helpers — dependency-free, canonical serialization primitives.
// Used to build UNAMBIGUOUS signed-message and AAD byte strings (see wire.ts).

const _enc = new TextEncoder();
const _dec = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return _enc.encode(s);
}
export function fromUtf8(b: Uint8Array): string {
  return _dec.decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff)
    throw new RangeError(`u32be out of range: ${n}`);
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

export function u64be(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn)
    throw new RangeError(`u64be out of range: ${n}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

/**
 * Length-prefixed concatenation: each field => u32be(len) || bytes, in order.
 * This is collision-free across differing field boundaries (unlike bare concat),
 * so two distinct field tuples can never serialize to the same byte string.
 */
export function concatLP(...fields: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    parts.push(u32be(f.length), f);
  }
  return concat(...parts);
}

const _HEX: readonly string[] = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0'),
);

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += _HEX[x]!;
  return s;
}

const CANONICAL_HEX = /^[0-9a-f]*$/; // canonical wire transport: lowercase hex only (even length)

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('hex length must be even');
  // Strictly canonical: reject uppercase, whitespace, sign, 0x/0o, and any non-hex char so the
  // transport is 1:1 (no malleable many-to-one decode such as "AB"/"ab" or parseInt's "-1"/"1g").
  if (!CANONICAL_HEX.test(h))
    throw new Error('invalid hex: non-canonical character');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Constant-time equality for equal-length arrays; fast false on length mismatch. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
