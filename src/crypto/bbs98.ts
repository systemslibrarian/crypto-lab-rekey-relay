import {
  g1,
  g1ToBytes,
  invScalar,
  isValidScalar,
  mulScalar,
  randomScalar,
  type G1Point,
} from './group';
import { deriveDek, open, seal, utf8 } from './kem';
import { fail, ok, type Bbs98Ciphertext, type Bbs98KeyPair, type Bbs98ReKey, type Outcome } from './types';

/**
 * BBS98 — Blaze, Bleumer and Strauss, "Divertible Protocols and Atomic Proxy
 * Cryptography", EUROCRYPT 1998.
 *
 * The construction is ElGamal with one extra move. Written additively in G1,
 * with r the group order and g the generator:
 *
 *   keygen        sk = a,  pk = [a]g
 *   encrypt to A  pick k and a random M in G1
 *                 c1 = M + [k]g          <- carries the message
 *                 c2 = [k]pk_A = [ka]g   <- carries the key
 *   decrypt by A  [k]g = [a^-1]c2,  M = c1 - [k]g
 *
 *   rekeygen      rk_{A->B} = b * a^-1 mod r
 *   re-encrypt    c2' = [rk]c2 = [ka * b/a]g = [kb]g,  c1 unchanged
 *   decrypt by B  [k]g = [b^-1]c2',  M = c1 - [k]g
 *
 * The a in the exponent cancels and a b lands in its place. That single line
 * is the entire idea of proxy re-encryption, and this is the smallest honest
 * way to write it.
 *
 * It also contains the flaw the whole page is about. rk is a SCALAR equal to
 * b/a. The proxy holds it. Bob holds b. b divided by rk is a — Alice's private
 * key, in one modular division, with no cryptanalysis of any kind. See
 * `collude`.
 *
 * A second consequence of rk being a scalar: the proxy can invert it. rk^-1 =
 * a/b re-encrypts in the other direction with no one's consent, which is what
 * "bidirectional" means. See `invertReKey`.
 */

export function keygen(label: string): Bbs98KeyPair {
  const sk = randomScalar();
  return { label, sk, pk: g1.multiply(sk) };
}

/** Rebuild a key pair from a known scalar. Used by the KAT and claims suites. */
export function keypairFromScalar(label: string, sk: bigint): Bbs98KeyPair {
  if (!isValidScalar(sk)) throw new RangeError('sk out of range');
  return { label, sk, pk: g1.multiply(sk) };
}

/**
 * Encrypt to `target`.
 *
 * `M` is a uniform point of G1 obtained as [m]g for a uniform m; HKDF turns its
 * compressed encoding into the AES-GCM key that actually protects the bytes.
 * The AEAD's additional data is c1's encoding — the half the proxy must not
 * touch — so any tampering there surfaces as an authentication failure rather
 * than as a wrong plaintext.
 */
export async function encrypt(
  target: Bbs98KeyPair | { pk: G1Point; label?: string },
  plaintext: string
): Promise<Bbs98Ciphertext> {
  const k = randomScalar();
  const m = randomScalar();
  const M = g1.multiply(m);
  const c1 = M.add(g1.multiply(k));
  const c2 = target.pk.multiply(k);
  const dek = await deriveDek(g1ToBytes(M), 'bbs98');
  const payload = await seal(dek, utf8.encode(plaintext), g1ToBytes(c1));
  return {
    scheme: 'bbs98',
    c1,
    c2,
    holder: target.pk,
    holderLabel: 'label' in target && target.label ? target.label : 'an unnamed key',
    payload,
    hops: 0,
  };
}

/**
 * Decrypt with `sk`.
 *
 * Returns null when the AEAD rejects — which is what a wrong key looks like
 * here, because a wrong key recovers a wrong M, which derives a wrong DEK,
 * which fails the tag. No plaintext is ever returned unauthenticated.
 */
export async function decrypt(kp: Bbs98KeyPair, ct: Bbs98Ciphertext): Promise<string | null> {
  let seed: Uint8Array;
  try {
    const kG = ct.c2.multiply(invScalar(kp.sk));
    // A crafted c1 = [k]g makes M the identity, which has no compressed
    // encoding — @noble refuses to serialize it ("bad point: ZERO"). Nothing on
    // this page can build such a ciphertext, but "never throw across a module
    // boundary" is an invariant of this codebase rather than a property of the
    // inputs it happens to receive, so a degenerate recovery fails closed here
    // exactly like a wrong key does.
    seed = g1ToBytes(ct.c1.subtract(kG));
  } catch {
    return null;
  }
  const dek = await deriveDek(seed, 'bbs98');
  const pt = await open(dek, ct.payload, g1ToBytes(ct.c1));
  return pt === null ? null : utf8.decode(pt);
}

/** rk_{A->B} = b * a^-1 mod r. Requires BOTH private keys — see `isBidirectional`. */
export function rekeygen(from: Bbs98KeyPair, to: Bbs98KeyPair): Bbs98ReKey {
  return {
    scheme: 'bbs98',
    value: mulScalar(to.sk, invScalar(from.sk)),
    from: from.pk,
    to: to.pk,
    fromLabel: from.label,
    toLabel: to.label,
  };
}

/**
 * BBS98 rekeygen needs the delegatee's PRIVATE key, not just her public key.
 * That is a real operational cost — Alice cannot delegate to Bob without Bob's
 * participation, or without a trusted party that knows both secrets — and it is
 * the first of two things unidirectional schemes buy.
 */
export const isBidirectional = true;

/**
 * The proxy inverts its own key and relays the other way. Nobody consented.
 *
 * The exponents live mod r and r is PUBLIC, so this inversion needs no secret
 * at all. AFGH §1.1 on BBS98: "it is bidirectional; that is, the value b/a can
 * be used to divert ciphertexts from Alice to Bob and vice versa. Thus, this
 * scheme is only useful when the trust relationship between Alice and Bob is
 * mutual."
 */
export function invertReKey(rk: Bbs98ReKey): Bbs98ReKey {
  return {
    scheme: 'bbs98',
    value: invScalar(rk.value),
    from: rk.to,
    to: rk.from,
    fromLabel: rk.toLabel,
    toLabel: rk.fromLabel,
  };
}

/**
 * Check a re-encryption key against the two PUBLIC keys it claims to join.
 *
 *   [rk] pk_A  ==  pk_B     because  [b/a]([a]g) = [b]g
 *
 * BBS98's re-encryption key is publicly verifiable — anyone, including the
 * proxy, can confirm it is genuine using nothing secret. AFGH's is NOT: to
 * check g2^(a1 b2) you would need either b2 (secret) or g1^a1, and g1^a1 is
 * the collusion weak key, so it cannot be published.
 *
 * That inversion is worth sitting with. The scheme that surrenders the
 * delegator's private key on collusion is the one whose delegation key you can
 * audit; the scheme that protects it hands the proxy a 96-byte value it cannot
 * distinguish from a random point. It is why `RK_MISMATCH` means something
 * different in each scheme: a cryptographic check in BBS98, and pure
 * bookkeeping in AFGH.
 */
export function verifyReKey(rk: Bbs98ReKey): boolean {
  if (!isValidScalar(rk.value)) return false;
  return rk.from.multiply(rk.value).equals(rk.to);
}

/**
 * Compose two delegations into a third, with nobody's permission.
 *
 *   rk_{A->B} * rk_{B->C} = (b/a)(c/b) = c/a = rk_{A->C}
 *
 * BBS98 is TRANSITIVE. Blaze-Bleumer-Strauss say so themselves (p.10): "The
 * proxy relationship is necessarily transitive. If there are public proxy keys
 * pi_{A->B} and pi_{B->C}, then anyone can compute a proxy function for A->C."
 * Alice delegated to Bob. She did not delegate to Carol. The proxy can do it
 * anyway, and the delegation graph on this page shows the edge appear.
 */
export function composeReKeys(first: Bbs98ReKey, second: Bbs98ReKey): Outcome<Bbs98ReKey> {
  if (!first.to.equals(second.from)) {
    return fail(
      'RK_MISMATCH',
      `cannot compose ${first.fromLabel}->${first.toLabel} with ${second.fromLabel}->${second.toLabel}: the middle endpoints differ`
    );
  }
  return ok({
    scheme: 'bbs98',
    value: mulScalar(first.value, second.value),
    from: first.from,
    to: second.to,
    fromLabel: first.fromLabel,
    toLabel: second.toLabel,
  });
}

/**
 * BBS98 is MULTI-HOP. A re-encrypted ciphertext has exactly the same shape as a
 * fresh one — one ciphertext space, one decryption algorithm — so it can be
 * re-encrypted again without limit, at constant size. AFGH cannot; that
 * contrast is the "One hop" tab.
 */
export const isMultiHop = true;

/**
 * The proxy's transform. Fail-closed on both counts it can check:
 *
 *  - MALFORMED_RK if the scalar is 0 or out of range. A zero rk would send
 *    every ciphertext to the identity point and quietly destroy it.
 *  - RK_MISMATCH if this ciphertext is not currently addressed to the key this
 *    rk was issued for. Skipping this check does not throw — it produces a
 *    well-formed ciphertext no one can open, which is strictly worse.
 */
export function reencrypt(ct: Bbs98Ciphertext, rk: Bbs98ReKey): Outcome<Bbs98Ciphertext> {
  if (!isValidScalar(rk.value)) {
    return fail('MALFORMED_RK', `rk = ${rk.value} is not a unit mod r`);
  }
  if (!ct.holder.equals(rk.from)) {
    return fail(
      'RK_MISMATCH',
      `this ciphertext is addressed to ${ct.holderLabel} (${shortPk(ct.holder)}); the installed key re-encrypts from ${rk.fromLabel} (${shortPk(rk.from)})`
    );
  }
  return ok({
    ...ct,
    c2: ct.c2.multiply(rk.value),
    holder: rk.to,
    holderLabel: rk.toLabel,
    hops: ct.hops + 1,
  });
}

/**
 * The collusion.
 *
 * The proxy contributes rk = b/a. The delegatee contributes b. One modular
 * division later the delegator's private key is on the table. Nothing here is
 * an approximation or a search: `recovered` is checked against the real scalar
 * for exact equality, and against Alice's published public key by recomputing
 * [recovered]g — an independent route to the same answer.
 */
export interface CollusionResult {
  readonly recovered: bigint;
  /** [recovered]g, recomputed so the match is shown rather than asserted. */
  readonly recoveredPk: G1Point;
  /** True when the recovered scalar IS the delegator's private key. */
  readonly exact: boolean;
  /** True when [recovered]g lands on the delegator's published public key. */
  readonly matchesPublicKey: boolean;
}

export function collude(rk: Bbs98ReKey, delegateeSk: bigint, delegatorPk: G1Point, delegatorSk: bigint): CollusionResult {
  const recovered = mulScalar(delegateeSk, invScalar(rk.value));
  const recoveredPk = g1.multiply(recovered);
  return {
    recovered,
    recoveredPk,
    exact: recovered === delegatorSk,
    matchesPublicKey: recoveredPk.equals(delegatorPk),
  };
}

function shortPk(p: G1Point): string {
  const hex = Array.from(g1ToBytes(p).slice(0, 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hex;
}
