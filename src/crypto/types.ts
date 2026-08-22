import type { G1Point, G2Point, GTElement } from './group';
import type { SealedPayload } from './kem';

/**
 * The five named failure conditions this lab can produce. Every one of them is
 * reachable by hand from the page — none is a theoretical branch.
 *
 * They are strings rather than an enum so the exact code the learner sees on
 * screen is the exact code in the source and in the tests.
 */
export type FailureCode =
  /** A re-encryption key was presented for a ciphertext it was not issued for. */
  | 'RK_MISMATCH'
  /** A level-1 ciphertext was presented for re-encryption. AFGH allows one hop. */
  | 'ALREADY_REENCRYPTED'
  /** A ciphertext was handed to the decryptor for the other level. */
  | 'WRONG_LEVEL'
  /** Not an error: the collusion succeeded and a private key fell out. */
  | 'COLLUSION_KEY_RECOVERED'
  /** A re-encryption key failed structural validation before any use. */
  | 'MALFORMED_RK';

export const FAILURE_CODES: readonly FailureCode[] = [
  'RK_MISMATCH',
  'ALREADY_REENCRYPTED',
  'WRONG_LEVEL',
  'COLLUSION_KEY_RECOVERED',
  'MALFORMED_RK',
];

/** One-line explanations, shown wherever a code is printed. */
export const FAILURE_TEXT: Record<FailureCode, string> = {
  RK_MISMATCH:
    'The proxy holds a re-encryption key issued for a different delegator. It refuses the transform rather than producing a ciphertext nobody can open.',
  ALREADY_REENCRYPTED:
    'This ciphertext has already made its one hop. Its key-carrying half now lives in the target group GT, and no pairing leads out of GT — so there is nothing left to transform.',
  WRONG_LEVEL:
    'The decryptor for the other level was invoked. Level-2 and level-1 ciphertexts have different shapes and different secrets open them.',
  COLLUSION_KEY_RECOVERED:
    "Not a failure of the code — a failure of the scheme. The proxy's key and the delegatee's key together reproduced the delegator's private key exactly.",
  MALFORMED_RK:
    'The re-encryption key failed structural validation: out of range, not on the curve, or not in the order-r subgroup. It is rejected before any point is touched.',
};

export type Scheme = 'bbs98' | 'afgh';

/** Success or a named failure. Never a bare throw across a module boundary. */
export type Outcome<T> = { ok: true; value: T } | { ok: false; code: FailureCode; detail: string };

export function ok<T>(value: T): Outcome<T> {
  return { ok: true, value };
}

export function fail<T>(code: FailureCode, detail: string): Outcome<T> {
  return { ok: false, code, detail };
}

// ── BBS98 ──────────────────────────────────────────────────────────────────

export interface Bbs98KeyPair {
  readonly label: string;
  /** The private key. In BBS98 this single scalar is the whole secret. */
  readonly sk: bigint;
  /** pk = [sk] g1. */
  readonly pk: G1Point;
}

/**
 * A BBS98 ciphertext.
 *
 *   c1 = M + [k] g1       the message-carrying half. The proxy NEVER touches it.
 *   c2 = [k] pk_target    the key-carrying half. The proxy's whole job.
 *
 * `holder` is the public key c2 is currently addressed to. It moves when the
 * proxy transforms; c1 does not.
 */
export interface Bbs98Ciphertext {
  readonly scheme: 'bbs98';
  readonly c1: G1Point;
  readonly c2: G1Point;
  readonly holder: G1Point;
  readonly holderLabel: string;
  readonly payload: SealedPayload;
  /** How many proxy transforms this ciphertext has been through. */
  readonly hops: number;
}

/** rk_{A->B} = b * a^-1 mod r. A SCALAR — which is exactly the problem. */
export interface Bbs98ReKey {
  readonly scheme: 'bbs98';
  readonly value: bigint;
  readonly from: G1Point;
  readonly to: G1Point;
  readonly fromLabel: string;
  readonly toLabel: string;
}

// ── AFGH ───────────────────────────────────────────────────────────────────

/**
 * An AFGH key pair carries TWO secrets, and the split is the reason the scheme
 * survives collusion.
 *
 *   a1  the MASTER secret. Encrypt to it, sign with it, delegate FROM it. It is
 *       the exponent that goes into every re-encryption key Alice issues.
 *   a2  the DELEGATION-ACCEPTANCE secret. Publishing g2^a2 is how a user
 *       signals "I am willing to receive delegations"; it is the secret that
 *       opens anything a proxy forwards.
 *
 * The paper (Ateniese-Fu-Green-Hohenberger, §3.1, "A Third Attempt") puts it
 * exactly that way: "A user can encrypt, sign, and delegate decryption rights
 * all under Z^{a1}; if the value g^{a2} is present, it signifies that the user
 * is willing to accept delegations."
 *
 * A re-encryption key A->B is g2^(a1 * b2): Alice's master exponent multiplied
 * onto Bob's published acceptance point. Bob can strip his own b2 back off,
 * which leaves g2^a1 — a real residual capability this lab shows rather than
 * denies — but g2^a1 is a POINT, and getting a1 back out of it is a discrete
 * logarithm.
 */
export interface AfghKeyPair {
  readonly label: string;
  /** a1, the master secret. */
  readonly a1: bigint;
  /** a2, the delegation-acceptance secret. */
  readonly a2: bigint;
  /** Z^a1, in GT. The published key everything is encrypted to. */
  readonly Za1: GTElement;
  /** g2^a2, in G2. Published only if this user accepts delegations. */
  readonly Ga2: G2Point;
}

/** The public half: exactly what an encryptor or delegator is allowed to see. */
export interface AfghPublicKey {
  readonly label: string;
  readonly Za1: GTElement;
  readonly Ga2: G2Point;
}

/**
 * Level 2 is the re-encryptable form; level 1 is the terminal form.
 *
 * "Single-hop" is later vocabulary (Canetti-Hohenberger 2007; Libert-Vergnaud
 * 2008) — AFGH never use the word, and record multi-hop unidirectional PRE as
 * an open problem in their conclusion. The property itself is structural: a
 * level-2 ciphertext's first component is in G1, a pairing INPUT group; a
 * level-1 ciphertext's is in GT, the pairing OUTPUT group, and no pairing
 * consumes a GT element.
 */
export type AfghLevel = 1 | 2;

export interface AfghCiphertextL2 {
  readonly scheme: 'afgh';
  readonly level: 2;
  /** alpha = g1^k, in G1. Note it carries NO key material at all. */
  readonly alpha: G1Point;
  /** beta = M * Z^(a1 k), in GT. The message-carrying half. */
  readonly beta: GTElement;
  readonly holder: AfghPublicKey;
  readonly payload: SealedPayload;
  readonly hops: 0;
}

export interface AfghCiphertextL1 {
  readonly scheme: 'afgh';
  readonly level: 1;
  /** alpha = Z^(a_i k), in GT. */
  readonly alpha: GTElement;
  /** beta = M * Z^k, in GT — carried through a re-encryption byte for byte. */
  readonly beta: GTElement;
  /**
   * Which secret component opens it: 1 for a native encryption under a1, 2 for
   * a native encryption under a2 AND for everything a proxy produces. The two
   * are indistinguishable, which is what AFGH call proxy invisibility.
   */
  readonly component: 1 | 2;
  readonly holder: AfghPublicKey;
  readonly payload: SealedPayload;
  readonly hops: 0 | 1;
}

export type AfghCiphertext = AfghCiphertextL1 | AfghCiphertextL2;

/**
 * rk_{A->B} = g2^(a1 * b2). A POINT in G2 — which is why the BBS98 division
 * has no analogue here.
 */
export interface AfghReKey {
  readonly scheme: 'afgh';
  readonly value: G2Point;
  readonly from: AfghPublicKey;
  readonly to: AfghPublicKey;
  readonly fromLabel: string;
  readonly toLabel: string;
}

export type AnyReKey = Bbs98ReKey | AfghReKey;
export type AnyCiphertext = Bbs98Ciphertext | AfghCiphertext;
