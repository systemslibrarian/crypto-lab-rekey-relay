import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { bytesToHex, g1, g1ToBytes, g2, g2ToBytes, hexToBytes, ORDER } from '../src/crypto/group';

/**
 * Known-answer tests against the published specifications of every primitive
 * this lab actually executes.
 *
 * A note on what is and is not here, because the honest answer matters more
 * than a bigger number. BBS98 and AFGH have NO standardized test vectors — no
 * RFC, no FIPS, no NIST CAVP set, and neither paper publishes one. There is
 * nothing to check them against, and inventing a vector by running this code
 * and freezing its output would be a self-consistency check wearing a KAT's
 * clothes. So the schemes are covered by algebraic property tests instead
 * (`bbs98.test.ts`, `afgh.test.ts`), and the KATs below pin down the
 * standardized machinery they are built out of:
 *
 *   - the BLS12-381 curve constants and generators, against
 *     draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1 and the ZCash/IETF
 *     compressed point encoding;
 *   - HKDF-SHA-256, against RFC 5869 Appendix A;
 *   - AES-256-GCM, against the Galois/Counter Mode specification's own test
 *     cases (McGrew & Viega; NIST SP 800-38D's reference set).
 *
 * The HKDF and GCM vectors go through the SAME WebCrypto calls `kem.ts` uses,
 * not a separate reference implementation, so a green run here is evidence
 * about the code path the page runs.
 */

// ── BLS12-381, draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1 ───────────

const SPEC_P =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const SPEC_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const SPEC_G1_X =
  0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn;
const SPEC_G1_Y =
  0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n;
const SPEC_G2_X0 =
  0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n;
const SPEC_G2_X1 =
  0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en;
const SPEC_G2_Y0 =
  0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n;
const SPEC_G2_Y1 =
  0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben;

/** Compressed encodings, ZCash/IETF form: 0x80 compression bit set on byte 0. */
const SPEC_G1_COMPRESSED =
  '97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb';
const SPEC_G2_COMPRESSED =
  '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e' +
  '024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8';

describe('KAT: BLS12-381 parameters (draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1)', () => {
  it('base field modulus p', () => {
    expect(bls.fields.Fp.ORDER).toBe(SPEC_P);
  });

  it('subgroup order r', () => {
    expect(bls.fields.Fr.ORDER).toBe(SPEC_R);
    expect(ORDER).toBe(SPEC_R);
  });

  it('G1 generator affine coordinates', () => {
    const a = g1.toAffine();
    expect(a.x).toBe(SPEC_G1_X);
    expect(a.y).toBe(SPEC_G1_Y);
  });

  it('G2 generator affine coordinates over Fp2', () => {
    const a = g2.toAffine() as { x: { c0: bigint; c1: bigint }; y: { c0: bigint; c1: bigint } };
    expect(a.x.c0).toBe(SPEC_G2_X0);
    expect(a.x.c1).toBe(SPEC_G2_X1);
    expect(a.y.c0).toBe(SPEC_G2_Y0);
    expect(a.y.c1).toBe(SPEC_G2_Y1);
  });

  it('G1 generator compressed encoding', () => {
    expect(bytesToHex(g1ToBytes(g1))).toBe(SPEC_G1_COMPRESSED);
  });

  it('G2 generator compressed encoding', () => {
    expect(bytesToHex(g2ToBytes(g2))).toBe(SPEC_G2_COMPRESSED);
  });
});

// ── HKDF-SHA-256, RFC 5869 Appendix A ──────────────────────────────────────

async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', copy(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: copy(salt), info: copy(info) },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

function copy(v: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(v.byteLength);
  new Uint8Array(out).set(v);
  return out;
}

function ramp(start: number, n: number): Uint8Array {
  return new Uint8Array(Array.from({ length: n }, (_, i) => start + i));
}

const HKDF_VECTORS = [
  {
    name: 'A.1 Test Case 1 — basic',
    ikm: hexToBytes('0b'.repeat(22)),
    salt: hexToBytes('000102030405060708090a0b0c'),
    info: hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
    len: 42,
    okm:
      '3cb25f25faacd57a90434f64d0362f2a' +
      '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
      '34007208d5b887185865',
  },
  {
    name: 'A.2 Test Case 2 — longer inputs and output',
    ikm: ramp(0x00, 80),
    salt: ramp(0x60, 80),
    info: ramp(0xb0, 80),
    len: 82,
    okm:
      'b11e398dc80327a1c8e7f78c596a4934' +
      '4f012eda2d4efad8a050cc4c19afa97c' +
      '59045a99cac7827271cb41c65e590e09' +
      'da3275600c2f09b8367793a9aca3db71' +
      'cc30c58179ec3e87c14c01d5c1f3434f' +
      '1d87',
  },
  {
    name: 'A.3 Test Case 3 — zero-length salt and info',
    ikm: hexToBytes('0b'.repeat(22)),
    salt: new Uint8Array(0),
    info: new Uint8Array(0),
    len: 42,
    okm:
      '8da4e775a563c18f715f802a063c5a31' +
      'b8a11f5c5ee1879ec3454e5f3c738d2d' +
      '9d201395faa4b61a96c8',
  },
] as const;

describe('KAT: HKDF-SHA-256 (RFC 5869 Appendix A), through the WebCrypto call kem.ts uses', () => {
  for (const v of HKDF_VECTORS) {
    it(v.name, async () => {
      const okm = await hkdfSha256(v.ikm, v.salt, v.info, v.len);
      expect(bytesToHex(okm)).toBe(v.okm);
    });
  }
});

// ── AES-256-GCM, the GCM specification's test cases ────────────────────────

async function gcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  pt: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', copy(key), 'AES-GCM', false, ['encrypt']);
  const out = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: copy(iv), additionalData: copy(aad), tagLength: 128 },
    k,
    copy(pt)
  );
  return new Uint8Array(out);
}

const GCM_KEY = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308';
const GCM_IV = 'cafebabefacedbaddecaf888';
const GCM_PT64 =
  'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
  '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255';
const GCM_PT60 = GCM_PT64.slice(0, 120);
const GCM_CT60 =
  '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
  '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662';

const GCM_VECTORS = [
  {
    name: 'Test Case 13 — AES-256, empty plaintext and AAD',
    key: '00'.repeat(32),
    iv: '00'.repeat(12),
    pt: '',
    aad: '',
    ct: '',
    tag: '530f8afbc74536b9a963b4f1c4cb738b',
  },
  {
    name: 'Test Case 14 — AES-256, one zero block',
    key: '00'.repeat(32),
    iv: '00'.repeat(12),
    pt: '00'.repeat(16),
    aad: '',
    ct: 'cea7403d4d606b6e074ec5d3baf39d18',
    tag: 'd0d1c8a799996bf0265b98b5d48ab919',
  },
  {
    name: 'Test Case 15 — AES-256, 64-byte plaintext, no AAD',
    key: GCM_KEY,
    iv: GCM_IV,
    pt: GCM_PT64,
    aad: '',
    ct: GCM_CT60 + '898015ad',
    tag: 'b094dac5d93471bdec1a502270e3cc6c',
  },
  {
    name: 'Test Case 16 — AES-256, 60-byte plaintext WITH additional authenticated data',
    key: GCM_KEY,
    iv: GCM_IV,
    pt: GCM_PT60,
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    ct: GCM_CT60,
    tag: '76fc6ece0f4e1768cddf8853bb2d551b',
  },
] as const;

describe('KAT: AES-256-GCM (Galois/Counter Mode specification), through the WebCrypto call kem.ts uses', () => {
  for (const v of GCM_VECTORS) {
    it(v.name, async () => {
      const out = await gcmSeal(hexToBytes(v.key), hexToBytes(v.iv), hexToBytes(v.pt), hexToBytes(v.aad));
      // WebCrypto appends the tag to the ciphertext; the spec lists them apart.
      expect(bytesToHex(out)).toBe(v.ct + v.tag);
    });
  }

  it('Test Case 16 fails authentication when the AAD is altered — the binding is real', async () => {
    const k = await crypto.subtle.importKey('raw', copy(hexToBytes(GCM_KEY)), 'AES-GCM', false, [
      'decrypt',
    ]);
    const sealed = hexToBytes(GCM_CT60 + '76fc6ece0f4e1768cddf8853bb2d551b');
    await expect(
      crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: copy(hexToBytes(GCM_IV)),
          additionalData: copy(hexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad3')),
          tagLength: 128,
        },
        k,
        copy(sealed)
      )
    ).rejects.toThrow();
  });
});
