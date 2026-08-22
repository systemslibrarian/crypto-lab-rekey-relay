import { describe, expect, it } from 'vitest';
import {
  collude,
  composeReKeys,
  decrypt,
  encrypt,
  invertReKey,
  isBidirectional,
  isMultiHop,
  keygen,
  keypairFromScalar,
  reencrypt,
  rekeygen,
} from '../src/crypto/bbs98';
import { divScalar, g1, g1ToBytes, invScalar, mulScalar, ORDER, randomScalar } from '../src/crypto/group';

const MSG = 'The relay carries the box, not the key to it.';

describe('BBS98 — round trips', () => {
  it('Alice encrypts to herself and reads it back', async () => {
    const alice = keygen('Alice');
    const ct = await encrypt(alice, MSG);
    expect(await decrypt(alice, ct)).toBe(MSG);
  });

  it('the proxy transforms and Bob reads the same plaintext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    const rk = rekeygen(alice, bob);
    const out = reencrypt(ct, rk);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await decrypt(bob, out.value)).toBe(MSG);
  });

  it('Bob cannot read it BEFORE the transform', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    expect(await decrypt(bob, ct)).toBeNull();
  });

  it('Alice cannot read it AFTER the transform — delegation moves the ciphertext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    const out = reencrypt(ct, rekeygen(alice, bob));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await decrypt(alice, out.value)).toBeNull();
  });

  it('a third party with an unrelated key reads nothing at either end', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const ct = await encrypt(alice, MSG);
    const out = reencrypt(ct, rekeygen(alice, bob));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await decrypt(carol, ct)).toBeNull();
    expect(await decrypt(carol, out.value)).toBeNull();
  });
});

describe('BBS98 — the exponent ledger, checked independently of the code path', () => {
  it('c2 tracks [k*a]g before and [k*b]g after, recomputed from scratch', async () => {
    const a = randomScalar();
    const b = randomScalar();
    const alice = keypairFromScalar('Alice', a);
    const bob = keypairFromScalar('Bob', b);
    const ct = await encrypt(alice, MSG);
    // Recover k independently: c2 = [k*a]g, so [a^-1]c2 = [k]g, and we can
    // confirm the transform lands on [k*b]g without ever calling reencrypt's
    // own arithmetic.
    const kG = ct.c2.multiply(invScalar(a));
    const out = reencrypt(ct, rekeygen(alice, bob));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.value.c2.equals(kG.multiply(b))).toBe(true);
  });

  it('the message half is byte-identical across the hop', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    const out = reencrypt(ct, rekeygen(alice, bob));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect([...g1ToBytes(out.value.c1)]).toEqual([...g1ToBytes(ct.c1)]);
    expect([...out.value.payload.ct]).toEqual([...ct.payload.ct]);
    expect([...out.value.payload.iv]).toEqual([...ct.payload.iv]);
  });

  it('rk really is b/a, checked against the scalars directly', () => {
    const a = randomScalar();
    const b = randomScalar();
    const rk = rekeygen(keypairFromScalar('A', a), keypairFromScalar('B', b));
    expect(rk.value).toBe(divScalar(b, a));
    expect(mulScalar(rk.value, a)).toBe(b);
  });
});

describe('BBS98 — the flaw', () => {
  it('COLLUSION_KEY_RECOVERED: proxy rk divided into Bob b yields Alice a exactly', () => {
    for (let i = 0; i < 8; i++) {
      const alice = keygen('Alice');
      const bob = keygen('Bob');
      const rk = rekeygen(alice, bob);
      const result = collude(rk, bob.sk, alice.pk, alice.sk);
      expect(result.exact).toBe(true);
      expect(result.recovered).toBe(alice.sk);
      // Independent route: the recovered scalar must reproduce the PUBLISHED
      // public key, which the collusion never touched.
      expect(result.matchesPublicKey).toBe(true);
      expect(result.recoveredPk.equals(g1.multiply(alice.sk))).toBe(true);
    }
  });

  it('the recovered key decrypts a ciphertext the colluders never saw', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const rk = rekeygen(alice, bob);
    // A message encrypted AFTER the collusion, never sent through the proxy.
    const later = await encrypt(alice, 'a message sent long after the delegation');
    const { recovered } = collude(rk, bob.sk, alice.pk, alice.sk);
    const impostor = keypairFromScalar('impostor', recovered);
    expect(await decrypt(impostor, later)).toBe('a message sent long after the delegation');
  });

  it('the collusion is symmetric: Alice and the proxy recover Bob too', () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const rk = rekeygen(alice, bob);
    // rk = b/a, so a * rk = b.
    expect(mulScalar(alice.sk, rk.value)).toBe(bob.sk);
  });

  it('bidirectional: the proxy inverts rk and relays Bob -> Alice unasked', async () => {
    expect(isBidirectional).toBe(true);
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const rk = rekeygen(alice, bob);
    const back = invertReKey(rk);
    expect(back.value).toBe(invScalar(rk.value));
    const toBob = await encrypt(bob, MSG);
    const diverted = reencrypt(toBob, back);
    expect(diverted.ok).toBe(true);
    if (!diverted.ok) return;
    expect(await decrypt(alice, diverted.value)).toBe(MSG);
  });

  it('transitive: rk(A->B) * rk(B->C) is a working rk(A->C) nobody authorised', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const composed = composeReKeys(rekeygen(alice, bob), rekeygen(bob, carol));
    expect(composed.ok).toBe(true);
    if (!composed.ok) return;
    expect(composed.value.value).toBe(divScalar(carol.sk, alice.sk));
    const ct = await encrypt(alice, MSG);
    const out = reencrypt(ct, composed.value);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await decrypt(carol, out.value)).toBe(MSG);
  });

  it('composition refuses when the middle endpoints differ', () => {
    const [a, b, c, d] = [keygen('A'), keygen('B'), keygen('C'), keygen('D')];
    const bad = composeReKeys(rekeygen(a, b), rekeygen(c, d));
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    expect(bad.code).toBe('RK_MISMATCH');
  });

  it('multi-hop: a re-encrypted ciphertext re-encrypts again, unbounded', async () => {
    expect(isMultiHop).toBe(true);
    const chain = [keygen('A'), keygen('B'), keygen('C'), keygen('D')];
    let ct = await encrypt(chain[0]!, MSG);
    for (let i = 0; i < chain.length - 1; i++) {
      const out = reencrypt(ct, rekeygen(chain[i]!, chain[i + 1]!));
      expect(out.ok).toBe(true);
      if (!out.ok) return;
      ct = out.value;
      expect(ct.hops).toBe(i + 1);
    }
    expect(await decrypt(chain[3]!, ct)).toBe(MSG);
  });
});

describe('BBS98 — fail-closed edges', () => {
  it('RK_MISMATCH when the ciphertext is addressed to someone else', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const toCarol = await encrypt(carol, MSG);
    const out = reencrypt(toCarol, rekeygen(alice, bob));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('RK_MISMATCH');
  });

  it('MALFORMED_RK on a zero scalar, which would erase every ciphertext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    const rk = { ...rekeygen(alice, bob), value: 0n };
    const out = reencrypt(ct, rk);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('MALFORMED_RK');
  });

  it('MALFORMED_RK on a scalar at or beyond r', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    for (const v of [ORDER, ORDER + 1n]) {
      const out = reencrypt(ct, { ...rekeygen(alice, bob), value: v });
      expect(out.ok).toBe(false);
      if (out.ok) return;
      expect(out.code).toBe('MALFORMED_RK');
    }
  });

  it('a corrupted rk that is still a valid scalar produces an unopenable ciphertext, not a wrong plaintext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encrypt(alice, MSG);
    const rk = rekeygen(alice, bob);
    const out = reencrypt(ct, { ...rk, value: mulScalar(rk.value, 2n) });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await decrypt(bob, out.value)).toBeNull();
  });

  it('tampering with the AEAD ciphertext is rejected by the tag', async () => {
    const alice = keygen('Alice');
    const ct = await encrypt(alice, MSG);
    const flipped = new Uint8Array(ct.payload.ct);
    flipped[0] = (flipped[0] ?? 0) ^ 1;
    expect(await decrypt(alice, { ...ct, payload: { ...ct.payload, ct: flipped } })).toBeNull();
  });

  it('splicing another ciphertext’s c1 is rejected — and the AAD is not what catches it', async () => {
    // Worth stating precisely, because the comment in `kem.ts` used to claim
    // more. c1 is both the AAD and the component the KEM derives M from, so a
    // spliced c1 changes the derived key and the tag fails regardless of the
    // binding. Removing the AAD entirely leaves this test green. What it does
    // prove is that a well-formed substitution yields NO plaintext rather than
    // a wrong one.
    const alice = keygen('Alice');
    const a = await encrypt(alice, MSG);
    const b = await encrypt(alice, 'a different message entirely');
    expect(g1ToBytes(a.c1)).not.toEqual(g1ToBytes(b.c1));
    expect(await decrypt(alice, { ...a, c1: b.c1 })).toBeNull();
    // The same payload under its own c1 still opens, so the rejection is the
    // swap and not a broken fixture.
    expect(await decrypt(alice, a)).toBe(MSG);
  });
});
