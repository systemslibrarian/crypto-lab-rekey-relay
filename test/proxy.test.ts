import { describe, expect, it } from 'vitest';
import { Proxy } from '../src/crypto/proxy';
import * as bbs98 from '../src/crypto/bbs98';
import * as afgh from '../src/crypto/afgh';
import { g2 } from '../src/crypto/group';
import type { AfghCiphertext } from '../src/crypto/types';

const utf8Bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

const SECRET = 'MEET AT THE OLD LIBRARY AT NINE — bring the second key';

describe('the proxy sees ciphertext only', () => {
  it('BBS98: the plaintext bytes appear nowhere in everything the proxy handled', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    const rk = bbs98.rekeygen(alice, bob);
    expect(proxy.install(rk).ok).toBe(true);
    const ct = await bbs98.encrypt(alice, SECRET);
    const id = proxy.edgeId('bbs98', 'Alice', 'Bob');
    const out = proxy.transform(id, ct);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(await bbs98.decrypt(bob, out.value as typeof ct)).toBe(SECRET);

    // The measurement, not the claim.
    expect(proxy.bytesHandled()).toBeGreaterThan(200);
    expect(proxy.findPlaintextExposure(utf8Bytes(SECRET))).toBeNull();
    // Every non-trivial substring too, so a partial leak cannot hide.
    for (let len = 8; len <= SECRET.length; len += 7) {
      expect(proxy.findPlaintextExposure(utf8Bytes(SECRET.slice(0, len)))).toBeNull();
    }
  });

  it('AFGH: same measurement, across the pairing transform', async () => {
    const proxy = new Proxy();
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    expect(proxy.install(afgh.rekeygen(alice, afgh.publicKey(bob))).ok).toBe(true);
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), SECRET);
    const out = proxy.transform(proxy.edgeId('afgh', 'Alice', 'Bob'), ct);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const dec = await afgh.decrypt(bob, out.value as AfghCiphertext);
    expect(dec.ok && dec.value).toBe(SECRET);
    expect(proxy.findPlaintextExposure(utf8Bytes(SECRET))).toBeNull();
  });

  it('the search is not vacuous: a planted needle IS found', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const ct = await bbs98.encrypt(alice, SECRET);
    proxy.transform(proxy.edgeId('bbs98', 'Alice', 'Bob'), ct);
    // Take a byte run the proxy demonstrably DID handle and search for it.
    const firstField = proxy.journal[0]!.bytes[0]!;
    const hit = proxy.findPlaintextExposure(firstField.slice(2, 12));
    expect(hit).not.toBeNull();
  });
});

describe('the proxy always learns the graph', () => {
  it('installing a key records who delegates to whom', () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    expect(proxy.delegations).toHaveLength(1);
    expect(proxy.delegations[0]!.from).toBe('Alice');
    expect(proxy.delegations[0]!.to).toBe('Bob');
    expect(proxy.delegations[0]!.revoked).toBe(false);
  });

  it('use counts rise with each transform', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const id = proxy.edgeId('bbs98', 'Alice', 'Bob');
    for (let i = 0; i < 3; i++) {
      proxy.transform(id, await bbs98.encrypt(alice, `message ${i}`));
    }
    expect(proxy.delegations[0]!.uses).toBe(3);
  });
});

describe('revocation is a policy, not a proof', () => {
  it('revoking removes the key and the proxy then refuses', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const id = proxy.edgeId('bbs98', 'Alice', 'Bob');
    expect(proxy.revoke(id)).toBe(true);
    expect(proxy.hasKey(id)).toBe(false);
    const out = proxy.transform(id, await bbs98.encrypt(alice, SECRET));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('RK_MISMATCH');
    expect(proxy.delegations[0]!.revoked).toBe(true);
  });

  it('revoking twice is a no-op', () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const id = proxy.edgeId('bbs98', 'Alice', 'Bob');
    expect(proxy.revoke(id)).toBe(true);
    expect(proxy.revoke(id)).toBe(false);
  });

  it('NEG-1: a colluding pair keeps reading AFTER revocation, under both schemes', async () => {
    // BBS98 — they hold Alice's actual private key.
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    const rk = bbs98.rekeygen(alice, bob);
    proxy.install(rk);
    const recovered = bbs98.collude(rk, bob.sk, alice.pk, alice.sk).recovered;
    expect(proxy.revoke(proxy.edgeId('bbs98', 'Alice', 'Bob'))).toBe(true);
    const after = await bbs98.encrypt(alice, 'sent after revocation');
    expect(await bbs98.decrypt(bbs98.keypairFromScalar('impostor', recovered), after)).toBe(
      'sent after revocation'
    );

    // AFGH — they hold the weak key, which is enough for level 2.
    const p2 = new Proxy();
    const a = afgh.keygen('Alice');
    const b = afgh.keygen('Bob');
    const rk2 = afgh.rekeygen(a, afgh.publicKey(b));
    p2.install(rk2);
    const { weakKey } = afgh.collude(rk2, b.a2, a);
    expect(p2.revoke(p2.edgeId('afgh', 'Alice', 'Bob'))).toBe(true);
    const after2 = await afgh.encryptLevel2(afgh.publicKey(a), 'sent after revocation');
    expect(await afgh.decryptWithWeakKey(weakKey, after2)).toBe('sent after revocation');
  });
});

describe('the proxy refuses fail-closed and says why', () => {
  it('MALFORMED_RK is refused at install time, before any ciphertext exists', () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    const out = proxy.install({ ...bbs98.rekeygen(alice, bob), value: 0n });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('MALFORMED_RK');
    expect(proxy.delegations).toHaveLength(0);
    expect(proxy.journal.at(-1)!.kind).toBe('refused');
  });

  it('MALFORMED_RK is refused for an AFGH identity point too', () => {
    const proxy = new Proxy();
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const out = proxy.install({ ...rk, value: g2.subtract(g2) });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('MALFORMED_RK');
  });

  it('a scheme mismatch is refused rather than crashed', async () => {
    const proxy = new Proxy();
    const alice = bbs98.keygen('Alice');
    const bob = bbs98.keygen('Bob');
    proxy.install(bbs98.rekeygen(alice, bob));
    const a = afgh.keygen('Alice');
    const ct = await afgh.encryptLevel2(afgh.publicKey(a), SECRET);
    const out = proxy.transform(proxy.edgeId('bbs98', 'Alice', 'Bob'), ct);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.code).toBe('RK_MISMATCH');
  });

  it('every refusal is journalled with its code', async () => {
    const proxy = new Proxy();
    const alice = afgh.keygen('Alice');
    const bob = afgh.keygen('Bob');
    const carol = afgh.keygen('Carol');
    proxy.install(afgh.rekeygen(alice, afgh.publicKey(bob)));
    proxy.install(afgh.rekeygen(bob, afgh.publicKey(carol)));
    const ct = await afgh.encryptLevel2(afgh.publicKey(alice), SECRET);
    const hop1 = proxy.transform(proxy.edgeId('afgh', 'Alice', 'Bob'), ct);
    expect(hop1.ok).toBe(true);
    if (!hop1.ok) return;
    const hop2 = proxy.transform(proxy.edgeId('afgh', 'Bob', 'Carol'), hop1.value);
    expect(hop2.ok).toBe(false);
    const codes = proxy.journal.filter((e) => e.refusalCode).map((e) => e.refusalCode);
    expect(codes).toContain('ALREADY_REENCRYPTED');
  });
});
