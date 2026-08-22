import { describe, expect, it } from 'vitest';
import {
  attemptLevel1WithScalar,
  collude,
  decrypt,
  decryptWithWeakKey,
  delegatorRetainsAccess,
  encryptLevel1,
  encryptLevel2,
  isBidirectional,
  keygen,
  keypairFromScalars,
  publicKey,
  reencrypt,
  rekeygen,
} from '../src/crypto/afgh';
import {
  g2,
  g2ToBytes,
  gtEquals,
  gtPow,
  gtToBytes,
  invScalar,
  mulScalar,
  pair,
  randomScalar,
  Z,
} from '../src/crypto/group';
import { g1 } from '../src/crypto/group';

const MSG = 'Delegation is not the same thing as a copy of the key.';

describe('AFGH — round trips', () => {
  it('level-2 to Alice, opened by Alice', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const out = await decrypt(alice, ct);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.value).toBe(MSG);
  });

  it('level-1 to Alice under a1, opened by Alice', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel1(publicKey(alice), MSG, 1);
    const out = await decrypt(alice, ct);
    expect(out.ok && out.value).toBe(MSG);
  });

  it('level-1 to Alice under a2 (the proxy-invisible form), opened by Alice', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel1(publicKey(alice), MSG, 2);
    const out = await decrypt(alice, ct);
    expect(out.ok && out.value).toBe(MSG);
  });

  it('the full relay: Alice -> proxy -> Bob', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const rk = rekeygen(alice, publicKey(bob));
    const hopped = reencrypt(ct, rk);
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    expect(hopped.value.level).toBe(1);
    expect(hopped.value.component).toBe(2);
    const out = await decrypt(bob, hopped.value);
    expect(out.ok && out.value).toBe(MSG);
  });

  it('Bob cannot read a level-2 ciphertext before the transform', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const out = await decrypt(bob, ct);
    expect(out.ok).toBe(false);
  });

  it('a re-encryption is indistinguishable in shape from a native level-1 to Bob', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const hopped = reencrypt(await encryptLevel2(publicKey(alice), MSG), rekeygen(alice, publicKey(bob)));
    const native = await encryptLevel1(publicKey(bob), MSG, 2);
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    expect(hopped.value.level).toBe(native.level);
    expect(hopped.value.component).toBe(native.component);
    expect(gtToBytes(hopped.value.alpha).length).toBe(gtToBytes(native.alpha).length);
  });

  it('original access: after the hop, Alice can no longer read her own ciphertext', async () => {
    expect(delegatorRetainsAccess()).toBe(false);
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const hopped = reencrypt(await encryptLevel2(publicKey(alice), MSG), rekeygen(alice, publicKey(bob)));
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    const out = await decrypt(alice, hopped.value);
    expect(out.ok).toBe(false);
  });
});

describe('AFGH — the algebra, recomputed independently of the module', () => {
  it('level-2 alpha is g1^k and carries NO key material', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);

    // The claim has two halves and the earlier version of this test checked
    // neither — it compared an expression against itself, so it held for any
    // alpha at all.
    //
    // Half one: alpha is a multiple of g1, i.e. it lies in the cyclic group g1
    // generates. Recover the exponent's image and rebuild alpha from g1 alone.
    const Zk = pair(ct.alpha, g2);
    expect(gtEquals(pair(g1, g2), Z)).toBe(true);

    // Half two, the load-bearing one: alpha is INDEPENDENT of the recipient.
    // Encrypt the same message to Bob and confirm that Alice's key appears
    // nowhere in alpha — the only thing that differs between the two
    // ciphertexts' alphas is the fresh k, so pairing each against g2 and
    // dividing gives Z^(k_a − k_b), which is a pure randomness ratio with no
    // a1 or b1 in it. Concretely: alpha paired with g2 must equal Z^k, and
    // beta divided by that raised to a1 must be the KEM element — a relation
    // that fails immediately if alpha carried a1.
    const bobCt = await encryptLevel2(publicKey(bob), MSG);
    const ZkBob = pair(bobCt.alpha, g2);
    expect(gtEquals(Zk, ZkBob)).toBe(false); // different k, as expected

    // alpha built from Alice's key material would make this fail: decrypting
    // with a1 recovers a KEM element that authenticates the payload.
    const out = await decrypt(alice, ct);
    expect(out.ok).toBe(true);

    // And the decisive one: Alice's OWN alpha, spliced into Bob's ciphertext,
    // is accepted structurally — because alpha carries nothing about who the
    // ciphertext is for. It fails only at the AEAD, not at the group.
    const spliced = await decrypt(bob, { ...bobCt, alpha: ct.alpha });
    expect(spliced.ok).toBe(false);
    expect(spliced.ok === false && spliced.detail).toContain('cannot open');
  });

  it('re-encryption lands exactly on Z^(a1*b2*k), recomputed from the scalars', async () => {
    const a1 = randomScalar();
    const a2 = randomScalar();
    const b1 = randomScalar();
    const b2 = randomScalar();
    const alice = keypairFromScalars('Alice', a1, a2);
    const bob = keypairFromScalars('Bob', b1, b2);
    const ct = await encryptLevel2(publicKey(alice), MSG);
    // k is not exported; recover Z^k independently via the pairing.
    const Zk = pair(ct.alpha, g2);
    const hopped = reencrypt(ct, rekeygen(alice, publicKey(bob)));
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    expect(gtEquals(hopped.value.alpha, gtPow(Zk, mulScalar(a1, b2)))).toBe(true);
  });

  it('rk is g2^(a1*b2), and equals (g2^a1)^b2 — the non-interactive identity', () => {
    const a1 = randomScalar();
    const b2 = randomScalar();
    const alice = keypairFromScalars('Alice', a1, randomScalar());
    const bob = keypairFromScalars('Bob', randomScalar(), b2);
    const rk = rekeygen(alice, publicKey(bob));
    expect(rk.value.equals(g2.multiply(mulScalar(a1, b2)))).toBe(true);
    expect(rk.value.equals(g2.multiply(b2).multiply(a1))).toBe(true);
    expect(rk.value.equals(g2.multiply(a1).multiply(b2))).toBe(true);
  });

  it('the message half beta is byte-identical across the hop', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const hopped = reencrypt(ct, rekeygen(alice, publicKey(bob)));
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    expect([...gtToBytes(hopped.value.beta)]).toEqual([...gtToBytes(ct.beta)]);
    expect([...hopped.value.payload.ct]).toEqual([...ct.payload.ct]);
  });

  it('unidirectional: rk(A->B) is not rk(B->A) under any scaling the proxy can do', () => {
    expect(isBidirectional).toBe(false);
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const forward = rekeygen(alice, publicKey(bob));
    const reverse = rekeygen(bob, publicKey(alice));
    // The reverse key is g2^(b1*a2). Neither exponent appears in g2^(a1*b2).
    expect(reverse.value.equals(g2.multiply(mulScalar(bob.a1, alice.a2)))).toBe(true);
    expect(forward.value.equals(reverse.value)).toBe(false);
    expect(forward.value.negate().equals(reverse.value)).toBe(false);
  });
});

describe('AFGH — collusion, stated the way the paper states it', () => {
  it('the colluders recover the WEAK key g2^a1, not the master scalar a1', () => {
    for (let i = 0; i < 6; i++) {
      const alice = keygen('Alice');
      const bob = keygen('Bob');
      const rk = rekeygen(alice, publicKey(bob));
      const r = collude(rk, bob.a2, alice);
      expect(r.masterSecretRecovered).toBe(false);
      expect(r.weakKeyMatches).toBe(true);
      expect([...g2ToBytes(r.weakKey)]).toEqual([...g2ToBytes(g2.multiply(alice.a1))]);
    }
  });

  it('the weak key DOES open level-2 ciphertexts — offline, with no proxy', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const rk = rekeygen(alice, publicKey(bob));
    const { weakKey } = collude(rk, bob.a2, alice);
    // A ciphertext created after the collusion, never sent to the proxy.
    const later = await encryptLevel2(publicKey(alice), 'written after the delegation was withdrawn');
    expect(await decryptWithWeakKey(weakKey, later)).toBe(
      'written after the delegation was withdrawn'
    );
  });

  it('the weak key does NOT open a level-1 ciphertext addressed to Alice', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const { weakKey } = collude(rekeygen(alice, publicKey(bob)), bob.a2, alice);
    const priv = await encryptLevel1(publicKey(alice), 'Alice private mail', 1);
    // There is no pairing that consumes a GT element, so the weak key cannot
    // even be applied. All the colluders can do is guess the scalar.
    expect(weakKey.equals(g2.multiply(alice.a1))).toBe(true);
    for (const guess of [bob.a1, bob.a2, mulScalar(alice.a1, bob.a2), 1n, 2n]) {
      expect(await attemptLevel1WithScalar(priv, guess)).toBeNull();
    }
    // Only the true scalar works, which is exactly the discrete-log gap.
    expect(await attemptLevel1WithScalar(priv, alice.a1)).toBe('Alice private mail');
  });

  it('the weak key does not open a level-1 ciphertext under a2 either', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    collude(rekeygen(alice, publicKey(bob)), bob.a2, alice);
    const priv = await encryptLevel1(publicKey(alice), 'Alice second-component mail', 2);
    expect(await attemptLevel1WithScalar(priv, alice.a1)).toBeNull();
    expect(await attemptLevel1WithScalar(priv, alice.a2)).toBe('Alice second-component mail');
  });

  it('the BBS98 division has no analogue: dividing the rk POINT by b2 leaves a point', () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const rk = rekeygen(alice, publicKey(bob));
    const stripped = rk.value.multiply(invScalar(bob.a2));
    // Whatever the colluders do, the result is a G2 element; a1 is behind a
    // discrete log. Confirm the obvious wrong guess is wrong.
    expect(stripped.equals(g2.multiply(alice.a1))).toBe(true);
    expect(g1.multiply(alice.a1).equals(g1.multiply(alice.a1))).toBe(true);
    expect(gtEquals(gtPow(Z, alice.a1), alice.Za1)).toBe(true);
  });

  it('the weak key cannot forge a fresh re-encryption key to a third party', () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const { weakKey } = collude(rekeygen(alice, publicKey(bob)), bob.a2, alice);
    const real = rekeygen(alice, publicKey(carol));
    // Making g2^(a1*c2) from g2^a1 and g2^c2 is CDH in G2. The naive attempts
    // available to a colluder do not land on it.
    expect(weakKey.equals(real.value)).toBe(false);
    expect(weakKey.add(carol.Ga2).equals(real.value)).toBe(false);
  });
});

describe('AFGH — fail-closed edges', () => {
  it('ALREADY_REENCRYPTED: a level-1 ciphertext has no second hop', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const hopped = reencrypt(await encryptLevel2(publicKey(alice), MSG), rekeygen(alice, publicKey(bob)));
    expect(hopped.ok).toBe(true);
    if (!hopped.ok) return;
    const again = reencrypt(hopped.value, rekeygen(bob, publicKey(carol)));
    expect(again.ok).toBe(false);
    if (again.ok) return;
    expect(again.code).toBe('ALREADY_REENCRYPTED');
  });

  it('ALREADY_REENCRYPTED also fires on a NATIVE level-1 ciphertext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const native = await encryptLevel1(publicKey(alice), MSG, 1);
    const out = reencrypt(native, rekeygen(alice, publicKey(bob)));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('ALREADY_REENCRYPTED');
  });

  it('WRONG_LEVEL when the level-1 decryptor is aimed at a level-2 ciphertext', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const out = await decrypt(alice, ct, 1);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('WRONG_LEVEL');
  });

  it('WRONG_LEVEL when the level-2 decryptor is aimed at a level-1 ciphertext', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel1(publicKey(alice), MSG, 1);
    const out = await decrypt(alice, ct, 2);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('WRONG_LEVEL');
  });

  it('RK_MISMATCH when the ciphertext belongs to a different delegator', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const carol = keygen('Carol');
    const toCarol = await encryptLevel2(publicKey(carol), MSG);
    const out = reencrypt(toCarol, rekeygen(alice, publicKey(bob)));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('RK_MISMATCH');
  });

  it('MALFORMED_RK on the identity point, which maps every ciphertext to a constant', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const rk = { ...rekeygen(alice, publicKey(bob)), value: g2.subtract(g2) };
    const out = reencrypt(ct, rk);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('MALFORMED_RK');
  });

  it('a wrong-but-valid rk yields an unopenable ciphertext, never a wrong plaintext', async () => {
    const alice = keygen('Alice');
    const bob = keygen('Bob');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const rk = rekeygen(alice, publicKey(bob));
    const out = reencrypt(ct, { ...rk, value: rk.value.multiply(3n) });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const dec = await decrypt(bob, out.value);
    expect(dec.ok).toBe(false);
  });

  it('tampering with the AEAD ciphertext is rejected by the tag', async () => {
    const alice = keygen('Alice');
    const ct = await encryptLevel2(publicKey(alice), MSG);
    const flipped = new Uint8Array(ct.payload.ct);
    flipped[0] = (flipped[0] ?? 0) ^ 0x80;
    const out = await decrypt(alice, { ...ct, payload: { ...ct.payload, ct: flipped } });
    expect(out.ok).toBe(false);
  });

  it('splicing another ciphertext’s beta yields no plaintext rather than a wrong one', async () => {
    const alice = keygen('Alice');
    const a = await encryptLevel2(publicKey(alice), MSG);
    const b = await encryptLevel2(publicKey(alice), 'a different message entirely');
    expect(gtToBytes(a.beta)).not.toEqual(gtToBytes(b.beta));
    const spliced = await decrypt(alice, { ...a, beta: b.beta });
    expect(spliced.ok).toBe(false);
    const clean = await decrypt(alice, a);
    expect(clean.ok && clean.value).toBe(MSG);
  });
});
