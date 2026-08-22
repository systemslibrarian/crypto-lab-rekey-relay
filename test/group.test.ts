import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  bytesToScalar,
  divScalar,
  fingerprint,
  g1,
  g1FromBytes,
  g1ToBytes,
  g2,
  g2FromBytes,
  g2ToBytes,
  gtDiv,
  gtEquals,
  gtMul,
  gtPow,
  gtToBytes,
  hexToBytes,
  invScalar,
  isValidScalar,
  mulScalar,
  ORDER,
  pair,
  randomGT,
  randomScalar,
  scalarToBytes,
  scalarToHex,
  Z,
} from '../src/crypto/group';

describe('scalars mod r', () => {
  it('rejection sampling stays in [1, r-1]', () => {
    for (let i = 0; i < 64; i++) {
      const s = randomScalar();
      expect(s).toBeGreaterThan(0n);
      expect(s).toBeLessThan(ORDER);
      expect(isValidScalar(s)).toBe(true);
    }
  });

  it('draws distinct scalars', () => {
    const seen = new Set<bigint>();
    for (let i = 0; i < 32; i++) seen.add(randomScalar());
    expect(seen.size).toBe(32);
  });

  it('inversion is a real inverse', () => {
    for (let i = 0; i < 16; i++) {
      const s = randomScalar();
      expect(mulScalar(s, invScalar(s))).toBe(1n);
    }
  });

  it('rejects 0, which has no inverse', () => {
    expect(() => invScalar(0n)).toThrow(RangeError);
    expect(isValidScalar(0n)).toBe(false);
    expect(isValidScalar(ORDER)).toBe(false);
  });

  it('division is multiplication by the inverse', () => {
    const a = randomScalar();
    const b = randomScalar();
    expect(divScalar(a, b)).toBe(mulScalar(a, invScalar(b)));
    expect(mulScalar(divScalar(a, b), b)).toBe(a);
  });

  it('scalar serialization round-trips at a fixed 32 bytes', () => {
    for (let i = 0; i < 16; i++) {
      const s = randomScalar();
      const b = scalarToBytes(s);
      expect(b.length).toBe(32);
      expect(bytesToScalar(b)).toBe(s);
      expect(scalarToHex(s)).toHaveLength(64);
    }
  });
});

describe('hex helpers', () => {
  it('round-trip', () => {
    const b = new Uint8Array([0, 1, 15, 16, 254, 255]);
    expect(bytesToHex(b)).toBe('00010f10feff');
    expect([...hexToBytes('00010F10FEFF')]).toEqual([...b]);
  });

  it('rejects non-hex and odd length', () => {
    expect(() => hexToBytes('abc')).toThrow(SyntaxError);
    expect(() => hexToBytes('zz')).toThrow(SyntaxError);
  });

  it('fingerprints are a prefix of the full hex', () => {
    const b = hexToBytes('deadbeefcafebabe0011');
    expect(fingerprint(b, 8)).toBe('deadbeef');
  });
});

describe('the three groups', () => {
  it('compressed encodings are the sizes the two schemes assume', () => {
    expect(g1ToBytes(g1).length).toBe(48);
    expect(g2ToBytes(g2).length).toBe(96);
    expect(gtToBytes(Z).length).toBe(576);
  });

  it('point encodings round-trip through the wire form', () => {
    const s = randomScalar();
    const p = g1.multiply(s);
    const q = g2.multiply(s);
    expect(g1FromBytes(g1ToBytes(p)).equals(p)).toBe(true);
    expect(g2FromBytes(g2ToBytes(q)).equals(q)).toBe(true);
  });

  it('parsing rejects garbage rather than returning a point', () => {
    const bad = new Uint8Array(48).fill(0xff);
    expect(() => g1FromBytes(bad)).toThrow();
    expect(() => g2FromBytes(new Uint8Array(96).fill(0xff))).toThrow();
  });

  it('the pairing is bilinear in both arguments', () => {
    const a = randomScalar();
    const b = randomScalar();
    const left = pair(g1.multiply(a), g2.multiply(b));
    const right = gtPow(Z, mulScalar(a, b));
    expect(gtEquals(left, right)).toBe(true);
    expect(gtEquals(pair(g1.multiply(a), g2), gtPow(Z, a))).toBe(true);
    expect(gtEquals(pair(g1, g2.multiply(b)), gtPow(Z, b))).toBe(true);
  });

  it('the pairing is non-degenerate', () => {
    // Z must not be the identity of GT, or every ciphertext would be constant.
    expect(gtEquals(Z, gtPow(Z, 0n))).toBe(false);
  });

  it('GT has order r: Z^r is the identity', () => {
    expect(gtEquals(gtPow(Z, ORDER), gtPow(Z, 0n))).toBe(true);
  });

  it('GT multiplication and division invert each other', () => {
    const { element: m } = randomGT();
    const k = randomScalar();
    const blinded = gtMul(m, gtPow(Z, k));
    expect(gtEquals(gtDiv(blinded, gtPow(Z, k)), m)).toBe(true);
  });

  it('a uniform GT element differs each draw', () => {
    const seen = new Set(Array.from({ length: 16 }, () => bytesToHex(gtToBytes(randomGT().element))));
    expect(seen.size).toBe(16);
  });
});
