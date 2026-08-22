import { describe, expect, it } from 'vitest';
import { deriveDek, open, seal, utf8 } from '../src/crypto/kem';
import { bytesToHex, g1, g1ToBytes, gtToBytes, randomGT, randomScalar } from '../src/crypto/group';

describe('KEM/DEM bridge', () => {
  it('the same group element derives the same key; a different one does not', async () => {
    const M = g1.multiply(randomScalar());
    const aad = new Uint8Array([1, 2, 3]);
    const a = await deriveDek(g1ToBytes(M), 'bbs98');
    const sealed = await seal(a, utf8.encode('hello'), aad);

    const again = await deriveDek(g1ToBytes(M), 'bbs98');
    expect(utf8.decode((await open(again, sealed, aad))!)).toBe('hello');

    const other = await deriveDek(g1ToBytes(g1.multiply(randomScalar())), 'bbs98');
    expect(await open(other, sealed, aad)).toBeNull();
  });

  it('the scheme label domain-separates: the same seed gives different keys', async () => {
    const seed = gtToBytes(randomGT().element);
    const aad = new Uint8Array(0);
    const withBbs = await seal(await deriveDek(seed, 'bbs98'), utf8.encode('x'), aad);
    const asAfgh = await open(await deriveDek(seed, 'afgh'), withBbs, aad);
    expect(asAfgh).toBeNull();
  });

  it('the AAD binding is enforced, not decorative', async () => {
    const dek = await deriveDek(g1ToBytes(g1.multiply(randomScalar())), 'bbs98');
    const sealed = await seal(dek, utf8.encode('bound'), new Uint8Array([9, 9]));
    expect(await open(dek, sealed, new Uint8Array([9, 8]))).toBeNull();
    expect(utf8.decode((await open(dek, sealed, new Uint8Array([9, 9])))!)).toBe('bound');
  });

  it('every seal draws a fresh 96-bit nonce', async () => {
    const dek = await deriveDek(g1ToBytes(g1.multiply(randomScalar())), 'bbs98');
    const seen = new Set<string>();
    for (let i = 0; i < 24; i++) {
      const s = await seal(dek, utf8.encode('same plaintext'), new Uint8Array(0));
      expect(s.iv.length).toBe(12);
      seen.add(bytesToHex(s.iv));
    }
    expect(seen.size).toBe(24);
  });

  it('the ciphertext carries a 128-bit tag', async () => {
    const dek = await deriveDek(g1ToBytes(g1.multiply(randomScalar())), 'bbs98');
    const s = await seal(dek, utf8.encode('abcd'), new Uint8Array(0));
    expect(s.ct.length).toBe(4 + 16);
  });

  it('open returns null rather than throwing on a corrupt tag', async () => {
    const dek = await deriveDek(g1ToBytes(g1.multiply(randomScalar())), 'bbs98');
    const s = await seal(dek, utf8.encode('abcd'), new Uint8Array(0));
    const bad = new Uint8Array(s.ct);
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    expect(await open(dek, { ...s, ct: bad }, new Uint8Array(0))).toBeNull();
  });

  it('round-trips arbitrary UTF-8 including multi-byte characters', async () => {
    const dek = await deriveDek(gtToBytes(randomGT().element), 'afgh');
    const msg = 'multibyte: ancient Greek, Japanese, and a trailing tab\t';
    const s = await seal(dek, utf8.encode(msg), new Uint8Array(0));
    expect(utf8.decode((await open(dek, s, new Uint8Array(0)))!)).toBe(msg);
  });

  it('an empty message still seals and opens', async () => {
    const dek = await deriveDek(gtToBytes(randomGT().element), 'afgh');
    const s = await seal(dek, utf8.encode(''), new Uint8Array(0));
    expect(utf8.decode((await open(dek, s, new Uint8Array(0)))!)).toBe('');
  });
});
