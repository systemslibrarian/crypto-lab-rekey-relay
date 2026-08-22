import {
  g1,
  g1FromBytes,
  g1ToBytes,
  g2,
  g2FromBytes,
  g2ToBytes,
  gtDiv,
  gtFromBytes,
  gtMul,
  gtPow,
  gtToBytes,
  invScalar,
  pair,
  randomGT,
  randomScalar,
  Z,
  type G1Point,
  type G2Point,
  type GTElement,
} from './group';
import { deriveDek, open, seal, utf8 } from './kem';
import {
  fail,
  ok,
  type AfghCiphertext,
  type AfghCiphertextL1,
  type AfghCiphertextL2,
  type AfghKeyPair,
  type AfghPublicKey,
  type AfghReKey,
  type Outcome,
} from './types';

/**
 * AFGH — Ateniese, Fu, Green and Hohenberger, "Improved Proxy Re-encryption
 * Schemes with Applications to Secure Distributed Storage."
 * NDSS 2005; extended version ePrint 2005/028; ACM TISSEC 9(1), 2006.
 *
 * This is the paper's THIRD ATTEMPT (§3.1) — the two-component-key scheme they
 * implemented and benchmarked, and the one people mean by "AFGH". It is not
 * the Second Attempt, which uses a one-component key pk = g^a and
 * rk = g^(b/a); that variant rests on a weaker, non-standard assumption and
 * leaks a different weak key (g^(1/a)), and is a common thing to mislabel.
 *
 * The paper writes a SYMMETRIC pairing e: G1 x G1 -> G2, with its "G2" meaning
 * the target group. BLS12-381 is Type-3 — e: G1 x G2 -> GT with no efficient
 * isomorphism — so the two source-group roles have to be split across G1 and
 * G2. The split is forced, not chosen: ReEncrypt pairs the level-2 ciphertext's
 * first component with the re-encryption key, so one of those has to be in G1
 * and the other in G2, and the public key follows the re-encryption key. The
 * page states the adaptation in the Scheme Card disclosure; the README's "What
 * Can Go Wrong" records what it does and does not preserve.
 *
 * With g1 in G1, g2 in G2 and Z = e(g1, g2) in GT:
 *
 *   keygen     sk = (a1, a2),  pk = (Z^a1 in GT,  g2^a2 in G2)
 *
 *   E2 to A    pick k, and M uniform in GT
 *   (level 2)  alpha = g1^k                 in G1   <- carries NO key material
 *              beta  = M * Z^(a1 k)         in GT   <- carries the message
 *   D2 by A    M = beta / e(alpha, g2)^a1
 *
 *   E1 to A    alpha = Z^(a_i k),  beta = M * Z^k,   i in {1, 2}
 *   (level 1)  D1 by A: M = beta / alpha^(1/a_i)
 *
 *   rekeygen   rk_{A->B} = (g2^b2)^a1 = g2^(a1 b2)  in G2
 *   re-encrypt alpha' = e(alpha, rk) = e(g1^k, g2^(a1 b2)) = Z^(a1 b2 k)
 *              beta'  = beta, byte for byte
 *              which is exactly a native level-1 ciphertext to B under b2,
 *              with k' = a1 k. B opens it with D1 and b2.
 *
 * NON-INTERACTIVE. Alice builds rk from her own a1 and Bob's PUBLISHED g2^a2.
 * BBS98 needs both private keys; this needs none of Bob's.
 *
 * UNIDIRECTIONAL. The reverse key would be g2^(b1 a2) — a different pair of
 * exponents, neither of which appears in g2^(a1 b2). There is no rearrangement
 * that produces it, which is the whole point.
 *
 * COLLUSION. See `collude`. The paper's claim is precise and this lab states it
 * the same way: the colluders recover the WEAK secret g2^a1, not a1. Table 1
 * scores collusion-safety "Yes*" with the footnote "* indicates master secret
 * key only", and this demo does not round that up.
 */

export function keygen(label: string): AfghKeyPair {
  const a1 = randomScalar();
  const a2 = randomScalar();
  return { label, a1, a2, Za1: gtPow(Z, a1), Ga2: g2.multiply(a2) };
}

export function keypairFromScalars(label: string, a1: bigint, a2: bigint): AfghKeyPair {
  return { label, a1, a2, Za1: gtPow(Z, a1), Ga2: g2.multiply(a2) };
}

export function publicKey(kp: AfghKeyPair): AfghPublicKey {
  return { label: kp.label, Za1: kp.Za1, Ga2: kp.Ga2 };
}

/**
 * Level-2 encryption: the re-encryptable form.
 *
 * Note what alpha = g1^k does NOT contain: any part of the recipient's key.
 * All of the key material is on the message side, in Z^(a1 k). That is the
 * inversion of roles that lets a proxy pair alpha against a re-encryption key
 * and land on a ciphertext for someone else — the same structural trick BBS98
 * plays with its recipient-free blinding factor, one group up.
 */
export async function encryptLevel2(
  target: AfghPublicKey,
  plaintext: string
): Promise<AfghCiphertextL2> {
  const k = randomScalar();
  const { element: M } = randomGT();
  const alpha = g1.multiply(k);
  const beta = gtMul(M, gtPow(target.Za1, k));
  const dek = await deriveDek(gtToBytes(M), 'afgh');
  const payload = await seal(dek, utf8.encode(plaintext), gtToBytes(beta));
  return { scheme: 'afgh', level: 2, alpha, beta, holder: target, payload, hops: 0 };
}

/**
 * Level-1 encryption: the terminal form, addressed straight to the recipient.
 *
 * `component` selects which secret opens it. Under a1 it is Alice's own private
 * mail — nothing a proxy ever touches, and the ciphertext this lab uses to show
 * what survives a collusion. Under a2 it is byte-shaped exactly like a
 * re-encryption, which is what AFGH call proxy invisibility: the recipient
 * cannot tell whether a proxy was involved.
 */
export async function encryptLevel1(
  target: AfghPublicKey,
  plaintext: string,
  component: 1 | 2 = 1
): Promise<AfghCiphertextL1> {
  const k = randomScalar();
  const { element: M } = randomGT();
  const alpha =
    component === 1 ? gtPow(target.Za1, k) : gtPow(pair(g1, target.Ga2), k);
  const beta = gtMul(M, gtPow(Z, k));
  const dek = await deriveDek(gtToBytes(M), 'afgh');
  const payload = await seal(dek, utf8.encode(plaintext), gtToBytes(beta));
  return { scheme: 'afgh', level: 1, alpha, beta, component, holder: target, payload, hops: 0 };
}

/**
 * Decrypt, dispatching on the ciphertext's own level.
 *
 * `expectLevel` exists so the page can invoke the WRONG decryptor on purpose.
 * The two levels hold their key-carrying half in different groups and are
 * opened by different secrets; running one through the other's routine is
 * `WRONG_LEVEL`, and it is a type error rather than a cryptographic failure.
 */
export async function decrypt(
  kp: AfghKeyPair,
  ct: AfghCiphertext,
  expectLevel?: 1 | 2
): Promise<Outcome<string>> {
  if (expectLevel !== undefined && ct.level !== expectLevel) {
    return fail(
      'WRONG_LEVEL',
      `this is a level-${ct.level} ciphertext and the level-${expectLevel} decryptor was invoked. ` +
        'Level 2 is opened by pairing alpha with g2 and raising to a1; level 1 by raising alpha to 1/a_i. ' +
        'The two alphas are not even in the same group.'
    );
  }
  // Level-1 alpha is the one value here that a delegatee raises to his OWN
  // SECRET after receiving it from the proxy. That is precisely the shape a
  // small-subgroup attack exploits, and BLS12-381 is not subgroup-secure, so
  // the element is re-parsed from its wire encoding — which checks order-r
  // membership — before any secret touches it. `Fp12.fromBytes` alone does
  // NOT check that; see `group.ts`.
  if (ct.level === 1) {
    try {
      gtFromBytes(gtToBytes(ct.alpha));
    } catch (e) {
      return fail('WRONG_LEVEL', `alpha failed GT subgroup validation: ${(e as Error).message}`);
    }
  }
  let seed: Uint8Array;
  try {
    const M =
      ct.level === 2
        ? gtDiv(ct.beta, gtPow(pair(ct.alpha, g2), kp.a1))
        : gtDiv(ct.beta, gtPow(ct.alpha, invScalar(ct.component === 1 ? kp.a1 : kp.a2)));
    seed = gtToBytes(M);
  } catch (e) {
    // A crafted level-2 alpha of the identity point makes `pair()` throw
    // ("pairing is not available for ZERO point"), and a beta outside GT can
    // make the division degenerate. Neither is reachable from this page — no
    // control here builds a ciphertext by hand — but the invariant is that no
    // module here throws across its boundary, so a malformed component is
    // reported as the shape violation it is rather than crashing the caller.
    return fail(
      'WRONG_LEVEL',
      `this is not a well-formed level-${ct.level} ciphertext: ${(e as Error).message}`
    );
  }
  const dek = await deriveDek(seed, 'afgh');
  const pt = await open(dek, ct.payload, gtToBytes(ct.beta));
  if (pt === null) {
    return fail(
      'WRONG_LEVEL',
      `the recovered group element derived a key that does not authenticate this ciphertext — ${kp.label} cannot open it`
    );
  }
  return ok(utf8.decode(pt));
}

/** rk_{A->B} = (g2^b2)^a1. Alice needs her own a1 and Bob's PUBLIC key. */
export function rekeygen(from: AfghKeyPair, to: AfghPublicKey): AfghReKey {
  return {
    scheme: 'afgh',
    value: to.Ga2.multiply(from.a1),
    from: publicKey(from),
    to,
    fromLabel: from.label,
    toLabel: to.label,
  };
}

export const isBidirectional = false;

/**
 * A re-encryption key here is NOT publicly verifiable, and that is structural.
 *
 * Checking rk = g2^(a1 b2) would need either b2, which is Bob's secret, or
 * g1^a1 — and g1^a1 is precisely the collusion weak key, so publishing it would
 * hand every level-2 ciphertext to the world. Neither is available, so a proxy
 * holding a 96-byte G2 point cannot tell a genuine rk from a random one.
 *
 * Consequence for this lab's failure codes: `RK_MISMATCH` under AFGH is
 * bookkeeping — the proxy is comparing labels, not verifying mathematics. Under
 * BBS98 the same code IS a cryptographic check (`bbs98.verifyReKey`). The
 * scheme that leaks the private key is the one whose delegation key you can
 * audit.
 */
export const reKeyIsPubliclyVerifiable = false;

/**
 * Self-delegation leaks Alice's own weak key.
 *
 * rk_{A->A} = g2^(a1 a2), and Alice knows a2, so anyone holding both recovers
 * g2^a1 — the same value a full Bob-and-proxy collusion produces, with only one
 * party involved. It is a legal call, so this lab does not block it; it names
 * it, because "delegate to yourself" is the kind of convenience a deployment
 * adds without thinking.
 */
export function isSelfDelegation(rk: AfghReKey): boolean {
  return rk.fromLabel === rk.toLabel;
}

/**
 * The proxy's transform.
 *
 * `ALREADY_REENCRYPTED` names a type error, not a computation that failed.
 * A level-1 ciphertext's alpha is an element of GT; `pair()` consumes
 * (G1, G2) and there is no map out of the target group, so there is no
 * expression that would re-encrypt it. The branch exists to say so in words —
 * this is a scheme that is single-hop BY CONSTRUCTION, not by agreement.
 */
export function reencrypt(ct: AfghCiphertext, rk: AfghReKey): Outcome<AfghCiphertextL1> {
  if (ct.level === 1) {
    return fail(
      'ALREADY_REENCRYPTED',
      'alpha is already in GT. The pairing maps G1 x G2 into GT and nothing maps out of GT, ' +
        'so there is no second transform to apply — the hop is a one-click ratchet.'
    );
  }
  let alphaPoint: G1Point;
  try {
    // The ciphertext gets the SAME wire round-trip the re-encryption key gets,
    // and for the same reason: a real proxy receives bytes. `g1FromBytes`
    // rejects points off the curve AND points outside the order-r subgroup —
    // BLS12-381 is not subgroup-secure, and pairing an off-subgroup point is
    // the primitive a small-subgroup attack is built from. The identity is
    // rejected separately because @noble will not pair it at all.
    if (ct.alpha.is0()) throw new Error('alpha is the identity point');
    alphaPoint = g1FromBytes(g1ToBytes(ct.alpha));
  } catch (e) {
    return fail(
      'WRONG_LEVEL',
      `this is not a well-formed level-2 ciphertext: ${(e as Error).message}`
    );
  }
  let rkPoint: G2Point;
  try {
    // A real proxy receives bytes. `g2FromBytes` rejects points off the curve
    // and points outside the order-r subgroup; the identity is rejected
    // separately because it is a valid point that would map every ciphertext
    // to the same constant.
    rkPoint = g2FromBytes(g2ToBytes(rk.value));
    if (rkPoint.is0()) throw new Error('identity point re-encrypts every ciphertext to a constant');
  } catch (e) {
    return fail('MALFORMED_RK', `re-encryption key failed validation: ${(e as Error).message}`);
  }
  if (!gtEq(ct.holder.Za1, rk.from.Za1)) {
    return fail(
      'RK_MISMATCH',
      `this ciphertext is addressed to ${ct.holder.label}; the installed key re-encrypts from ${rk.fromLabel}`
    );
  }
  return ok({
    scheme: 'afgh',
    level: 1,
    alpha: pair(alphaPoint, rkPoint),
    beta: ct.beta,
    component: 2,
    holder: rk.to,
    payload: ct.payload,
    hops: 1,
  });
}

/**
 * The collusion, stated the way the paper states it.
 *
 * The proxy holds rk = g2^(a1 b2). Bob holds b2. Scaling by b2^-1 strips his
 * own contribution back off and leaves g2^a1 — and that is where the unwinding
 * stops, because getting a1 out of g2^a1 is a discrete logarithm in G2.
 *
 * ePrint 2005/028, §3.1, verbatim: "If Bob and the proxy collude, they cannot
 * decrypt first-level encryptions intended for Alice. Indeed, they can recover
 * only the weak secret g^{a1} that can only be used to decrypt second-level
 * encryptions (which Bob and the proxy can already open anyway)."
 *
 * So "nothing usable emerges" would be false, and this lab does not say it.
 * g2^a1 is very usable: it opens every level-2 ciphertext under Alice's key,
 * forever, offline, with no proxy involved — and it is a 96-byte value the
 * colluders can hand to anyone (Remark 2.4; Table 1 scores non-transferability
 * "No" for every scheme in the paper, AFGH included). What it is NOT is a NEW
 * capability: opening Alice's level-2 ciphertexts is exactly what delegation
 * already authorised. And Alice keeps three things BBS98 would have lost: the
 * scalar a1, therefore her signing key; every level-1 ciphertext sent to her;
 * and the ability to issue re-encryption keys nobody else can forge (making a
 * fresh rk_{A->C} from g2^a1 and g2^c2 is CDH).
 */
export interface AfghCollusionResult {
  /** g2^a1, reconstructed from rk and the delegatee's own a2. */
  readonly weakKey: G2Point;
  /** Recomputed independently as g2^a1, so the match is shown, not asserted. */
  readonly weakKeyMatches: boolean;
  /** Always false. a1 appears in no transmitted value except as an exponent. */
  readonly masterSecretRecovered: boolean;
}

export function collude(
  rk: AfghReKey,
  delegateeA2: bigint,
  delegator: AfghKeyPair
): AfghCollusionResult {
  const weakKey = rk.value.multiply(invScalar(delegateeA2));
  return {
    weakKey,
    weakKeyMatches: weakKey.equals(g2.multiply(delegator.a1)),
    masterSecretRecovered: false,
  };
}

/**
 * Open a level-2 ciphertext with the weak key alone — no a1, no proxy, no
 * re-encryption key. This is what turns the collusion residue from a caption
 * into a demonstration, and it is the same function that shows why deleting rk
 * revokes nothing.
 */
export async function decryptWithWeakKey(
  weakKey: G2Point,
  ct: AfghCiphertextL2
): Promise<string | null> {
  const M = gtDiv(ct.beta, pair(ct.alpha, weakKey));
  const dek = await deriveDek(gtToBytes(M), 'afgh');
  const pt = await open(dek, ct.payload, gtToBytes(ct.beta));
  return pt === null ? null : utf8.decode(pt);
}

/**
 * Try the weak key against a level-1 ciphertext — the thing it must not open.
 *
 * There is no pairing that consumes a GT element, so g2^a1 cannot even be
 * APPLIED to alpha. The only move left is to guess the scalar, and this runs
 * the real level-1 decryptor with whatever scalar the caller guesses. It
 * returns null for every guess but the true one, which is the point: the gap
 * between holding g2^a1 and holding a1 is a discrete logarithm.
 */
export async function attemptLevel1WithScalar(
  ct: AfghCiphertextL1,
  guess: bigint
): Promise<string | null> {
  const M = gtDiv(ct.beta, gtPow(ct.alpha, invScalar(guess)));
  const dek = await deriveDek(gtToBytes(M), 'afgh');
  const pt = await open(dek, ct.payload, gtToBytes(ct.beta));
  return pt === null ? null : utf8.decode(pt);
}

/**
 * Original access (AFGH Table 1, property 4, scored "Yes-dagger" = achievable
 * with extra overhead).
 *
 * After the proxy replaces alpha = g1^k with Z^(a1 b2 k), the ciphertext is
 * addressed to Bob's b2 and Alice can no longer read it. That is a genuine
 * operational cost of the scheme as written, not a bug in this implementation,
 * and the page says so rather than hiding it behind a stored copy.
 */
export function delegatorRetainsAccess(): boolean {
  return false;
}

function gtEq(a: GTElement, b: GTElement): boolean {
  const x = gtToBytes(a);
  const y = gtToBytes(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}
