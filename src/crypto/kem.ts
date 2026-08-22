/**
 * The KEM/DEM bridge.
 *
 * Both schemes on this page encrypt a GROUP ELEMENT, not a message: BBS98's
 * plaintext slot holds a point in G1, AFGH's holds an element of GT. That is
 * how the papers are written, and it is not a limitation to hide — it is why
 * every real deployment of public-key encryption is hybrid.
 *
 * So the demo does what a deployment does. The scheme carries a random group
 * element M (the KEM), HKDF-SHA-256 turns M's canonical serialization into a
 * 256-bit data-encryption key, and AES-256-GCM encrypts the actual bytes the
 * learner typed (the DEM). Both halves are WebCrypto — `SubtleCrypto.deriveBits`
 * and `SubtleCrypto.encrypt` — so the code path under test is the one the
 * browser ships, and RFC 5869 and the GCM specification's own test vectors
 * apply to it directly (see `test/kat.test.ts`).
 *
 * The DEM ciphertext is bound with AES-GCM's additional authenticated data to
 * the one ciphertext component the proxy never touches — BBS98's `c1`, AFGH's
 * `beta`. That component survives a re-encryption byte for byte, so the tag
 * survives the proxy while any tampering with it surfaces as an authentication
 * failure rather than as a wrong plaintext.
 *
 * BE PRECISE ABOUT HOW MUCH THAT BUYS, because it is less than it looks and an
 * earlier version of this comment called it "load-bearing". It is not. In both
 * of these schemes the AAD component is ALSO the component the KEM derives its
 * key from: BBS98 recovers M as `c1 − [k]g`, AFGH as `beta / Z^(a1·k)`. Alter
 * either one and the recovered group element changes, so the derived key
 * changes, so the tag fails — with or without the AAD. Removing the binding
 * entirely and re-running the suite confirms it: only the isolated primitive
 * test in `kem.test.ts` notices.
 *
 * So the binding is defence in depth, not the mechanism. It is kept because it
 * makes the intent explicit at the call site, it costs nothing, and it stops
 * being redundant the moment anyone changes what the KEM derives from — which
 * is exactly the kind of edit that would otherwise silently remove a check.
 */

const HKDF_INFO_PREFIX = 'crypto-lab-rekey-relay/v1/';

/** 256-bit DEK derived from a serialized group element. */
export async function deriveDek(
  seed: Uint8Array,
  scheme: 'bbs98' | 'afgh'
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', toBuffer(seed), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      // A fixed, published salt. HKDF's salt is not a secret and this demo has
      // no place to store one; the extract step still domain-separates because
      // `info` carries the scheme.
      salt: new TextEncoder().encode('crypto-lab-rekey-relay/hkdf-salt/v1'),
      info: new TextEncoder().encode(HKDF_INFO_PREFIX + scheme + '/dek'),
    },
    ikm,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export interface SealedPayload {
  /** 96-bit GCM nonce. Fresh per encryption; never reused, never re-derived. */
  readonly iv: Uint8Array;
  /** AES-256-GCM ciphertext with its 128-bit tag appended. */
  readonly ct: Uint8Array;
}

export async function seal(
  dek: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<SealedPayload> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(iv), additionalData: toBuffer(aad), tagLength: 128 },
    dek,
    toBuffer(plaintext)
  );
  return { iv, ct: new Uint8Array(ct) };
}

/** Returns null on any authentication failure — never throws a raw DOMException. */
export async function open(
  dek: CryptoKey,
  payload: SealedPayload,
  aad: Uint8Array
): Promise<Uint8Array | null> {
  try {
    const pt = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBuffer(payload.iv),
        additionalData: toBuffer(aad),
        tagLength: 128,
      },
      dek,
      toBuffer(payload.ct)
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/**
 * A fresh `ArrayBuffer` copy of a view.
 *
 * WebCrypto accepts a `BufferSource`, but a `Uint8Array` that is a view into a
 * larger buffer is passed with its offset ignored by some engines' typings;
 * copying removes the whole class of confusion for a few dozen bytes.
 */
function toBuffer(view: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(view.byteLength);
  new Uint8Array(out).set(view);
  return out;
}

export const utf8 = {
  encode: (s: string): Uint8Array => new TextEncoder().encode(s),
  decode: (b: Uint8Array): string => new TextDecoder().decode(b),
};
