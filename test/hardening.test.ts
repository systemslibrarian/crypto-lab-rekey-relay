import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import * as afgh from '../src/crypto/afgh';
import type { AfghPublicKey } from '../src/crypto/types';
import * as bbs98 from '../src/crypto/bbs98';
import { Proxy } from '../src/crypto/proxy';
import {
  bytesToHex,
  g1ToBytes,
  g2,
  g2ToBytes,
  gtFromBytes,
  gtToBytes,
  isInGT,
  ORDER,
  randomScalar,
  Z,
} from '../src/crypto/group';

/**
 * Properties this lab claims on the page, checked here rather than asserted
 * there. Each one corresponds to a specific thing the page says out loud.
 */

describe('the two AFGH key components must be independent (page: "the split is the reason it survives")', () => {
  it('a2 = a1 is a TOTAL break: the public key alone opens every level-2 ciphertext', async () => {
    const a1 = randomScalar();
    // The degenerate key: both components the same scalar.
    const degenerate = afgh.keypairFromScalars('Degenerate', a1, a1);
    const ct = await afgh.encryptLevel2(afgh.publicKey(degenerate), 'this should not be readable');
    // pk.Ga2 = [a2]g2 = [a1]g2, which IS the collusion weak key. Anyone holding
    // the PUBLIC key can now run the weak-key decryptor.
    expect(degenerate.Ga2.equals(g2.multiply(a1))).toBe(true);
    expect(await afgh.decryptWithWeakKey(degenerate.Ga2, ct)).toBe('this should not be readable');
  });

  it('with independent components the same attack fails', async () => {
    const proper = afgh.keygen('Proper');
    const ct = await afgh.encryptLevel2(afgh.publicKey(proper), 'this should not be readable');
    expect(await afgh.decryptWithWeakKey(proper.Ga2, ct)).toBeNull();
  });

  it('keygen draws the two components independently', () => {
    for (let i = 0; i < 32; i++) {
      const kp = afgh.keygen('X');
      expect(kp.a1).not.toBe(kp.a2);
    }
  });
});

describe('GT subgroup membership is checked, because BLS12-381 is not subgroup-secure', () => {
  it('a genuine GT element passes', () => {
    expect(isInGT(Z)).toBe(true);
    expect(isInGT(bls.fields.Fp12.pow(Z, randomScalar()))).toBe(true);
  });

  it('a one-bit perturbation is rejected', () => {
    const bytes = gtToBytes(Z);
    const bad = new Uint8Array(bytes);
    bad[0] = (bad[0] ?? 0) ^ 1;
    expect(() => gtFromBytes(bad)).toThrow(RangeError);
  });

  it('the identity of Fp12 is in GT but a wrong length is refused', () => {
    expect(isInGT(bls.fields.Fp12.ONE)).toBe(true);
    expect(() => gtFromBytes(new Uint8Array(575))).toThrow(RangeError);
  });

  it('Z has order exactly r', () => {
    expect(isInGT(bls.fields.Fp12.pow(Z, ORDER))).toBe(true);
    expect(bls.fields.Fp12.eql(bls.fields.Fp12.pow(Z, ORDER), bls.fields.Fp12.ONE)).toBe(true);
  });
});

describe('re-encryption keys: verifiable in BBS98, not in AFGH (page: the inversion)', () => {
  it('BBS98 rk is checkable from the two public keys and nothing secret', () => {
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    const rk = bbs98.rekeygen(alice, bob);
    expect(bbs98.verifyReKey(rk)).toBe(true);
    expect(bbs98.verifyReKey({ ...rk, value: rk.value + 1n })).toBe(false);
  });

  it('AFGH publishes nothing that would let the proxy check its rk', () => {
    expect(afgh.reKeyIsPubliclyVerifiable).toBe(false);
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    // A random G2 point is structurally indistinguishable from the real one:
    // same group, same length, same encoding.
    const bogus = g2.multiply(randomScalar());
    expect(g2ToBytes(bogus).length).toBe(g2ToBytes(rk.value).length);
    // The value that WOULD verify it, g1^a1, is the collusion weak key and so
    // cannot be published — which is exactly why the check does not exist.
    expect(bytesToHex(g2ToBytes(g2.multiply(alice.a1)))).toBe(
      bytesToHex(g2ToBytes(afgh.collude(rk, bob.a2, alice).weakKey))
    );
  });
});

describe('self-delegation leaks the delegator’s own weak key', () => {
  it('rk(A→A) = [a1·a2]g2, and A knows a2', () => {
    const alice = afgh.keygen('Alice');
    const rk = afgh.rekeygen(alice, afgh.publicKey(alice));
    expect(afgh.isSelfDelegation(rk)).toBe(true);
    const leaked = afgh.collude(rk, alice.a2, alice);
    expect(leaked.weakKeyMatches).toBe(true);
    expect(leaked.weakKey.equals(g2.multiply(alice.a1))).toBe(true);
  });

  it('a normal delegation is not flagged as self-delegation', () => {
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    expect(afgh.isSelfDelegation(afgh.rekeygen(alice, afgh.publicKey(bob)))).toBe(false);
  });
});

describe('rogue-key registration: neither scheme proves possession', () => {
  it('AFGH: registering someone else’s public half produces a bit-identical rk', () => {
    const alice = afgh.keygen('Alice');
    const carol = afgh.keygen('Carol');
    // Mallory registers Carol's published Ga2 as his own.
    const mallory: AfghPublicKey = { label: 'Mallory', Za1: carol.Za1, Ga2: carol.Ga2 };
    const toCarol = afgh.rekeygen(alice, afgh.publicKey(carol));
    const toMallory = afgh.rekeygen(alice, mallory);
    expect(bytesToHex(g2ToBytes(toMallory.value))).toBe(bytesToHex(g2ToBytes(toCarol.value)));
  });

  it('AFGH: and CAROL, not Mallory, is the one who can read the result', async () => {
    const alice = afgh.keygen('Alice');
    const carol = afgh.keygen('Carol');
    const mallory = afgh.keygen('Mallory');
    const rogue = { label: 'Mallory', Za1: mallory.Za1, Ga2: carol.Ga2 };
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), 'for whoever holds the right a2');
    const hopped = afgh.reencrypt(ct, afgh.rekeygen(alice, rogue));
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    const byCarol = await afgh.decrypt(carol, hopped.value);
    const byMallory = await afgh.decrypt(mallory, hopped.value);
    expect(byCarol.ok && byCarol.value).toBe('for whoever holds the right a2');
    expect(byMallory.ok).toBe(false);
  });
});

describe('re-encryption is publicly linkable in both schemes', () => {
  it('BBS98: c1 is byte-identical, so an observer links input to output', async () => {
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    const before = await bbs98.encrypt(alice, 'anything');
    const after = bbs98.reencrypt(before, bbs98.rekeygen(alice, bob));
    expect(after.ok).toBe(true);
    if (!after.ok) return;
    expect(bytesToHex(g1ToBytes(after.value.c1))).toBe(bytesToHex(g1ToBytes(before.c1)));
  });

  it('AFGH: beta is byte-identical, so the same observation works', async () => {
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    const before = await afgh.encryptLevel2(afgh.publicKey(alice), 'anything');
    const after = afgh.reencrypt(before, afgh.rekeygen(alice, afgh.publicKey(bob)));
    expect(after.ok).toBe(true);
    if (!after.ok) return;
    expect(bytesToHex(gtToBytes(after.value.beta))).toBe(bytesToHex(gtToBytes(before.beta)));
  });

  it('and the link is visible in the proxy journal without any secret', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const ct = await bbs98.encrypt(alice, 'anything');
    proxy.transform(proxy.edgeId('bbs98', 'Alice', 'Bob'), ct);
    const inEntry = proxy.journal.find((e) => e.kind === 'ciphertext-in');
    const outEntry = proxy.journal.find((e) => e.kind === 'ciphertext-out');
    expect(inEntry?.fields[0]?.hex).toBe(outEntry?.fields[0]?.hex);
  });
});

describe('the two schemes never share a scalar', () => {
  it('a BBS98 key and an AFGH key generated together are unrelated', () => {
    const b = bbs98.keygen('Alice');
    const a = afgh.keygen('Alice');
    expect(b.sk).not.toBe(a.a1);
    expect(b.sk).not.toBe(a.a2);
  });
});

describe('degenerate ciphertext components fail closed rather than throwing', () => {
  it('BBS98: a crafted c1 that recovers the identity returns null, not an exception', async () => {
    const alice = bbs98.keygen('Alice');
    const ct = await bbs98.encrypt(alice, 'x');
    // c1 = [k]g makes M = c1 − [k]g = O, which has no compressed encoding.
    const forged = { ...ct, c1: ct.c2.multiply(bls.fields.Fr.inv(alice.sk)) };
    await expect(bbs98.decrypt(alice, forged)).resolves.toBeNull();
  });

  it('AFGH: a level-2 alpha of the identity is refused by the decryptor', async () => {
    const alice = afgh.keygen('Alice');
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), 'x');
    const forged = { ...ct, alpha: ct.alpha.subtract(ct.alpha) };
    const out = await afgh.decrypt(alice, forged);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('WRONG_LEVEL');
    expect(out.detail).toContain('not a well-formed level-2 ciphertext');
  });

  it('AFGH: a level-2 alpha of the identity is refused by the proxy transform', async () => {
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), 'x');
    const forged = { ...ct, alpha: ct.alpha.subtract(ct.alpha) };
    const out = afgh.reencrypt(forged, afgh.rekeygen(alice, afgh.publicKey(bob)));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('WRONG_LEVEL');
    expect(out.detail).toContain('identity point');
  });

  it('AFGH: a level-1 alpha outside GT is refused before any secret touches it', async () => {
    const alice = afgh.keygen('Alice');
    const ct = await afgh.encryptLevel1(afgh.publicKey(alice), 'x', 1);
    const bytes = gtToBytes(ct.alpha);
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    const forged = { ...ct, alpha: bls.fields.Fp12.fromBytes(bytes) as typeof ct.alpha };
    const out = await afgh.decrypt(alice, forged);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('WRONG_LEVEL');
    expect(out.detail).toContain('GT subgroup');
  });
});
