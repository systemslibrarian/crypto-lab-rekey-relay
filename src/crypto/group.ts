import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

/**
 * The one group this lab runs on: BLS12-381, a Type-3 (asymmetric) pairing
 * friendly curve.
 *
 *   G1  points on E(F_p),   compressed to 48 bytes
 *   G2  points on E'(F_p2), compressed to 96 bytes
 *   GT  the order-r subgroup of F_p12*, 576 bytes uncompressed
 *   r   the prime subgroup order shared by all three
 *   e   the pairing e: G1 x G2 -> GT, bilinear and non-degenerate
 *
 * Both schemes on this page live here. BBS98 needs only a prime-order group
 * where DDH is hard and uses G1; AFGH needs the pairing and uses all three.
 * Running them on the same curve is what makes the two re-encryption keys
 * directly comparable on screen: one is a SCALAR mod r, the other is a POINT
 * in G2, and that difference is the whole collusion story.
 *
 * Why DDH in G1 is still assumed hard here even though a pairing exists: the
 * pairing takes one argument from G1 and one from G2, and BLS12-381 is Type-3
 * — there is no efficiently computable homomorphism G1 -> G2. So the standard
 * "pair the two halves and compare" DDH distinguisher, which does break DDH in
 * a symmetric (Type-1) pairing group, has nothing to pair against. This is the
 * SXDH assumption, and it is what makes ElGamal (hence BBS98) sound in G1.
 */
export const Fr = bls.fields.Fr;
export const Fp12 = bls.fields.Fp12;

/** Prime order of G1, G2 and GT. */
export const ORDER: bigint = Fr.ORDER;

export type G1Point = InstanceType<typeof bls.G1.Point>;
export type G2Point = InstanceType<typeof bls.G2.Point>;
export type GTElement = ReturnType<typeof bls.pairing>;

/** Generators. */
export const g1: G1Point = bls.G1.Point.BASE;
export const g2: G2Point = bls.G2.Point.BASE;

/** Z = e(g1, g2), the GT generator every AFGH ciphertext is written against. */
export const Z: GTElement = bls.pairing(g1, g2);

export const G1_BYTES = 48;
export const G2_BYTES = 96;
export const GT_BYTES = 576;

/** e(P, Q). @noble/curves takes (G1, G2) in that order. */
export function pair(p: G1Point, q: G2Point): GTElement {
  return bls.pairing(p, q);
}

// ── Scalars ────────────────────────────────────────────────────────────────

/**
 * A uniform scalar in [1, r-1], by rejection sampling.
 *
 * Rejection, not `x mod r`: reducing a 256-bit draw modulo r biases the low
 * end of the range, and while the bias is tiny for BLS12-381's r it is exactly
 * the kind of shortcut this lab exists to not take. A zero draw is rejected
 * too — 0 has no inverse, and every secret here gets inverted somewhere.
 */
export function randomScalar(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf);
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    if (v > 0n && v < ORDER) return v;
  }
}

/** Modular inverse in Z_r. Throws on 0, which is the only non-invertible case. */
export function invScalar(x: bigint): bigint {
  const norm = ((x % ORDER) + ORDER) % ORDER;
  if (norm === 0n) throw new RangeError('scalar 0 has no inverse mod r');
  return Fr.inv(norm);
}

export function mulScalar(a: bigint, b: bigint): bigint {
  return Fr.mul(((a % ORDER) + ORDER) % ORDER, ((b % ORDER) + ORDER) % ORDER);
}

/** a / b mod r — the single operation that ends BBS98. */
export function divScalar(a: bigint, b: bigint): bigint {
  return mulScalar(a, invScalar(b));
}

export function isValidScalar(x: bigint): boolean {
  return x > 0n && x < ORDER;
}

// ── Serialization ──────────────────────────────────────────────────────────

const HEX = '0123456789abcdef';

export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += HEX[x >> 4]! + HEX[x & 15]!;
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.trim().toLowerCase().replace(/^0x/, '');
  if (h.length % 2 !== 0 || !/^[0-9a-f]*$/.test(h)) throw new SyntaxError('not hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function scalarToBytes(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = ((x % ORDER) + ORDER) % ORDER;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function bytesToScalar(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function scalarToHex(x: bigint): string {
  return bytesToHex(scalarToBytes(x));
}

export function g1ToBytes(p: G1Point): Uint8Array {
  return p.toBytes(true);
}

export function g2ToBytes(p: G2Point): Uint8Array {
  return p.toBytes(true);
}

export function gtToBytes(x: GTElement): Uint8Array {
  return Fp12.toBytes(x);
}

/**
 * Is this Fp12 element actually in GT?
 *
 * `Fp12.fromBytes` validates NOTHING — unlike `G1.Point.fromBytes` and
 * `G2.Point.fromBytes`, which check both curve membership and the order-r
 * subgroup. And BLS12-381 is not subgroup-secure: the cofactors of all three
 * groups contain prime factors smaller than r (GT's is divisible by 4513), so
 * small-subgroup attacks on GT are a live concern rather than a theoretical
 * one. Every place this lab raises a value it RECEIVED to a secret exponent —
 * a delegatee opening a level-1 ciphertext the proxy handed him is exactly
 * that shape — has to check first.
 *
 * The test is complete, not heuristic: Fp12* is the multiplicative group of a
 * finite field and therefore cyclic, so { x : x^r = 1 } is exactly the unique
 * order-r subgroup, which is GT. It costs one 255-bit Fp12 exponentiation.
 */
export function isInGT(x: GTElement): boolean {
  return Fp12.eql(Fp12.pow(x, ORDER), Fp12.ONE);
}

/** Parse a GT element from the wire, rejecting anything outside the subgroup. */
export function gtFromBytes(b: Uint8Array): GTElement {
  if (b.length !== GT_BYTES) throw new RangeError(`expected ${GT_BYTES} bytes, got ${b.length}`);
  const x = Fp12.fromBytes(b) as GTElement;
  if (!isInGT(x)) throw new RangeError('element is not in the order-r subgroup GT');
  return x;
}

/**
 * Parse a compressed G1 point, rejecting anything off-curve or outside the
 * order-r subgroup. @noble/curves runs both checks in `fromBytes`; this
 * wrapper exists so the failure reaches the UI as a named cause rather than as
 * a library string.
 */
export function g1FromBytes(b: Uint8Array): G1Point {
  return bls.G1.Point.fromBytes(b) as G1Point;
}

export function g2FromBytes(b: Uint8Array): G2Point {
  return bls.G2.Point.fromBytes(b) as G2Point;
}

export function g1Equals(a: G1Point, b: G1Point): boolean {
  return a.equals(b);
}

export function g2Equals(a: G2Point, b: G2Point): boolean {
  return a.equals(b);
}

export function gtEquals(a: GTElement, b: GTElement): boolean {
  return Fp12.eql(a, b);
}

export function gtMul(a: GTElement, b: GTElement): GTElement {
  return Fp12.mul(a, b);
}

export function gtDiv(a: GTElement, b: GTElement): GTElement {
  return Fp12.mul(a, Fp12.inv(b));
}

export function gtPow(a: GTElement, e: bigint): GTElement {
  return Fp12.pow(a, ((e % ORDER) + ORDER) % ORDER);
}

/** A uniform element of GT: Z^m for a uniform m. */
export function randomGT(): { element: GTElement; exponent: bigint } {
  const m = randomScalar();
  return { element: gtPow(Z, m), exponent: m };
}

/** A short, stable display fingerprint. Never used as a security check. */
export function fingerprint(bytes: Uint8Array, chars = 12): string {
  return bytesToHex(bytes).slice(0, chars);
}
