import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import * as afgh from '../src/crypto/afgh';
import * as bbs98 from '../src/crypto/bbs98';
import {
  bytesToHex,
  divScalar,
  g1,
  g1ToBytes,
  g2,
  g2ToBytes,
  gtPow,
  gtToBytes,
  pair,
  scalarToHex,
  Z,
} from '../src/crypto/group';

/**
 * Pinned scheme vectors — and an honest label for what they are.
 *
 * These are NOT specification known-answer tests. BBS98 and AFGH have no
 * standardized vectors at all; see `kat.test.ts` for the ones that do exist and
 * the reasoning about the gap. What these are is a TRANSCRIPTION check: small
 * hand-checkable scalars, with the expected group elements written out below in
 * full, so that a mis-transcribed exponent anywhere in `bbs98.ts` or `afgh.ts`
 * fails loudly.
 *
 * Two things make them worth having despite the caveat:
 *
 *  1. The expected hex was produced by a SEPARATE derivation, written against
 *     the raw @noble API from the papers' own equations, not by running this
 *     repo's modules and freezing the output. Freezing your own output tests
 *     nothing.
 *  2. Each test re-derives the value a second way here, directly from the
 *     library, and asserts all three agree: the pinned constant, the direct
 *     derivation, and the module under test. A bug has to be present in all
 *     three places to survive.
 *
 * The exponents these catch are the two most commonly mis-transcribed lines in
 * the literature: BBS98's rk orientation (b·a⁻¹, not a·b⁻¹ — the a·b⁻¹ form
 * belongs to the SIGNATURE cryptosystem in the same paper), and AFGH's
 * level-2 decryption exponent (a1, not 1/a1 — 1/a1 belongs to the Second
 * Attempt, which is a different scheme).
 */

// ── BBS98:  a = 7, b = 11, k = 5, m = 3 ────────────────────────────────────

const A = 7n;
const B = 11n;
const K = 5n;
const M_EXP = 3n;

const V_M = '89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224';
const V_C1 = 'a85ae765588126f5e860d019c0e26235f567a9c0c0b2d8ff30f3e8d436b1082596e5e7462d20f5be3764fd473e57f9cf';
const V_C2 = 'a60d5589316a5e16e1d9bb03db45136afb9a3d6e97d350256129ee32a8e33396907dc44d2211762967d88d3e2840f71b';
const V_RK = '108faa3073a8c8c12be3b125b83bb125551b176e24920d246db6db6d92492494';
const V_C2_PRIME =
  '89db41a6183c2fe47cf54d1e00c3cfaae53df634a32cccd5cf0c0a73e95ee0450fc3d060bb6878780fbf5f30d9e29aac';

describe('pinned vectors: BBS98 with a=7, b=11, k=5, m=3', () => {
  it('M = [3]g1', () => {
    expect(bytesToHex(g1ToBytes(g1.multiply(M_EXP)))).toBe(V_M);
  });

  it('c1 = M + [k]g1', () => {
    expect(bytesToHex(g1ToBytes(g1.multiply(M_EXP).add(g1.multiply(K))))).toBe(V_C1);
  });

  it('c2 = [k]pk_A = [k·a]g1', () => {
    const alice = bbs98.keypairFromScalar('Alice', A);
    expect(bytesToHex(g1ToBytes(alice.pk.multiply(K)))).toBe(V_C2);
  });

  it('rk = b·a⁻¹ mod r — the orientation that makes the proxy work', () => {
    const alice = bbs98.keypairFromScalar('Alice', A);
    const bob = bbs98.keypairFromScalar('Bob', B);
    const rk = bbs98.rekeygen(alice, bob);
    expect(scalarToHex(rk.value)).toBe(V_RK);
    // Third derivation, independent of both: b/a computed straight from Fr.
    expect(rk.value).toBe(divScalar(B, A));
    // And the negative: the SIGNATURE-scheme orientation is a different value.
    expect(scalarToHex(divScalar(A, B))).not.toBe(V_RK);
  });

  it("c2' = [rk]c2 = [k·b]g1, and equals a fresh encryption to Bob with the same k", () => {
    const alice = bbs98.keypairFromScalar('Alice', A);
    const bob = bbs98.keypairFromScalar('Bob', B);
    const rk = bbs98.rekeygen(alice, bob);
    const c2 = alice.pk.multiply(K);
    const c2p = c2.multiply(rk.value);
    expect(bytesToHex(g1ToBytes(c2p))).toBe(V_C2_PRIME);
    // Perfect key switching: identical to Encrypt(pk_B, ·) with the same k.
    expect(bytesToHex(g1ToBytes(bob.pk.multiply(K)))).toBe(V_C2_PRIME);
  });

  it('collusion: b · rk⁻¹ = a = 7', () => {
    const alice = bbs98.keypairFromScalar('Alice', A);
    const bob = bbs98.keypairFromScalar('Bob', B);
    const rk = bbs98.rekeygen(alice, bob);
    const r = bbs98.collude(rk, bob.sk, alice.pk, alice.sk);
    expect(r.recovered).toBe(7n);
    expect(r.exact).toBe(true);
    expect(r.matchesPublicKey).toBe(true);
  });

  it('the re-encryption key verifies against the two public keys alone', () => {
    const alice = bbs98.keypairFromScalar('Alice', A);
    const bob = bbs98.keypairFromScalar('Bob', B);
    expect(bbs98.verifyReKey(bbs98.rekeygen(alice, bob))).toBe(true);
    const carol = bbs98.keypairFromScalar('Carol', 13n);
    expect(bbs98.verifyReKey({ ...bbs98.rekeygen(alice, bob), to: carol.pk })).toBe(false);
    expect(bbs98.verifyReKey({ ...bbs98.rekeygen(alice, bob), value: 0n })).toBe(false);
  });
});

// ── AFGH:  a1 = 7, a2 = 13, b1 = 17, b2 = 19, k = 5, m = 3 ────────────────

const A1 = 7n;
const A2 = 13n;
const B1 = 17n;
const B2 = 19n;

const V_A2_PUB =
  '8bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7' +
  '152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c';
const V_B2_PUB =
  'ad52c7a82fece99279de7a49439c0ff8463a637cc6003320275d69549442c95184fd75ee5e7122e5575af7432e515929' +
  '02b29192945df0a74eed138e431962f1d39978202d247335ffbf29d8a02e982c69e96b58d7d92528baf5c422ed633f1f';
const V_L2_ALPHA =
  'b0e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc';
const V_RK_AB =
  'ae33d74806e5f26e4f8124e8ab9d9e462b3e0ffe3ae7a6a38006c37db3fc27e3902595cf02ab2c678e3b3a90332568b0' +
  '10c4317934ae7a39eaa25a6075103589b005c1a0ff96cd0f4c6a5247fde71de044da7f8ff677f8f0d9f3de64a3e15e12';
const V_WEAK =
  '8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8' +
  '049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c';
/** First 40 bytes of the 576-byte GT elements; enough to catch a transcription slip. */
const V_L2_BETA_PREFIX = '0e93af73ec6ed970decc88ec1b7d0831f765d2c1d0cfb0c4e4ca33cb640bb32a7bcd16c7879fabb3';
const V_L1_ALPHA_PREFIX = '10bc2c7b16b211f84a13cc0634ec4b074c347ea210739b10e095851b2295f2a5b514b9b935a9fa0e';

describe('pinned vectors: AFGH with a1=7, a2=13, b1=17, b2=19, k=5, m=3', () => {
  const alice = afgh.keypairFromScalars('Alice', A1, A2);
  const bob = afgh.keypairFromScalars('Bob', B1, B2);

  it('pk.Ga2 = [a2]g2 — the published "I accept delegations" half', () => {
    expect(bytesToHex(g2ToBytes(alice.Ga2))).toBe(V_A2_PUB);
    expect(bytesToHex(g2ToBytes(bob.Ga2))).toBe(V_B2_PUB);
  });

  it('pk.Za1 = Z^a1 lives in GT, not in a source group', () => {
    expect(gtToBytes(alice.Za1).length).toBe(576);
    expect(bytesToHex(gtToBytes(alice.Za1))).toBe(bytesToHex(gtToBytes(gtPow(Z, A1))));
  });

  it('level-2 alpha = [k]g1 and carries no key material', () => {
    expect(bytesToHex(g1ToBytes(g1.multiply(5n)))).toBe(V_L2_ALPHA);
  });

  it('level-2 beta = M · Z^(a1·k)', () => {
    const beta = bls.fields.Fp12.mul(gtPow(Z, M_EXP), gtPow(alice.Za1, K));
    expect(bytesToHex(gtToBytes(beta)).slice(0, 80)).toBe(V_L2_BETA_PREFIX);
  });

  it('rk = [a1·b2]g2, and equals [a1]([b2]g2) — the non-interactive identity', () => {
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    expect(bytesToHex(g2ToBytes(rk.value))).toBe(V_RK_AB);
    expect(bytesToHex(g2ToBytes(g2.multiply(B2).multiply(A1)))).toBe(V_RK_AB);
    expect(bytesToHex(g2ToBytes(g2.multiply(A1).multiply(B2)))).toBe(V_RK_AB);
  });

  it("re-encryption lands on Z^(a1·b2·k) — alpha' from the real pairing", () => {
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const alphaPrime = pair(g1.multiply(K), rk.value);
    expect(bytesToHex(gtToBytes(alphaPrime)).slice(0, 80)).toBe(V_L1_ALPHA_PREFIX);
    expect(bytesToHex(gtToBytes(gtPow(Z, A1 * B2 * K)))).toBe(bytesToHex(gtToBytes(alphaPrime)));
  });

  it('the weak key is [a1]g2 — depends on a1 and NOT on b1', () => {
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const r = afgh.collude(rk, B2, alice);
    expect(bytesToHex(g2ToBytes(r.weakKey))).toBe(V_WEAK);
    expect(bytesToHex(g2ToBytes(g2.multiply(A1)))).toBe(V_WEAK);
    expect(r.masterSecretRecovered).toBe(false);
    // Not [1/a1]g2 — that is the Second Attempt's weak key, a different scheme.
    expect(bytesToHex(g2ToBytes(g2.multiply(bls.fields.Fr.inv(A1))))).not.toBe(V_WEAK);
  });

  it('level-2 decryption uses a1, NOT 1/a1 — the transcription trap', async () => {
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), 'exponent direction matters');
    const out = await afgh.decrypt(alice, ct);
    expect(out.ok && out.value).toBe('exponent direction matters');
    // The Second Attempt's exponent direction fails here, which is the point.
    const wrong = afgh.keypairFromScalars('wrong', bls.fields.Fr.inv(A1), A2);
    const bad = await afgh.decrypt(wrong, ct);
    expect(bad.ok).toBe(false);
  });

  it('b1 is never used in delegation at all', () => {
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const bobWithOtherB1 = afgh.keypairFromScalars('Bob', 999n, B2);
    const rk2 = afgh.rekeygen(alice, afgh.publicKey(bobWithOtherB1));
    expect(bytesToHex(g2ToBytes(rk.value))).toBe(bytesToHex(g2ToBytes(rk2.value)));
    expect(B1).toBe(17n);
  });
});
