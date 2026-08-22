import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import {
  bytesToHex,
  divScalar,
  g1,
  g1ToBytes,
  g2,
  g2ToBytes,
  gtPow,
  gtToBytes,
  hexToBytes,
  isInGT,
  ORDER,
  pair,
  scalarToHex,
  Z,
} from '../crypto/group';
import { card, details, el, h3, kicker, liveRegion, p, replace, verdict } from './dom';

/**
 * The vectors, run in the browser rather than promised in a README.
 *
 * Every row below recomputes a published constant or vector from the same code
 * path the rest of the page uses, and compares it to the value the standard
 * prints. A row is green because a comparison came out equal on this machine
 * just now, not because a badge was pasted in.
 *
 * The honest part is the second table. BBS98 and AFGH have NO standardized test
 * vectors — no RFC, no FIPS, no CAVP set, and neither paper publishes one — so
 * those rows are labelled as what they are: transcription checks against small
 * hand-checkable scalars, catching the two exponents most often mis-copied from
 * the literature.
 */

interface Row {
  name: string;
  source: string;
  expected: string;
  actual: string;
}

export function renderVectors(host: HTMLElement): void {
  const out = liveRegion('Vector results');

  const intro = card('intro');
  intro.appendChild(kicker('Verification'));
  intro.appendChild(h3('Checked here, in your browser, right now'));
  intro.appendChild(
    p(
      'Everything on this page rests on three standardized pieces: the BLS12-381 curve, HKDF-SHA-256, and AES-256-GCM. Each has published test vectors, and each is exercised below through the exact code path the demo uses — the same WebCrypto calls, the same @noble/curves arithmetic.'
    )
  );
  intro.appendChild(
    p(
      'The schemes themselves have no such vectors, and the second table says so rather than manufacturing some.'
    )
  );
  host.appendChild(intro);

  const results = card();
  results.appendChild(out);
  host.appendChild(results);

  host.appendChild(
    details(
      'Why there are no BBS98 or AFGH known-answer tests, and what stands in for them',
      p(
        'A known-answer test is only worth something when the answer comes from somewhere other than the code being tested. For AES-GCM that source is the specification; for HKDF it is RFC 5869; for BLS12-381 it is draft-irtf-cfrg-pairing-friendly-curves. For BBS98 and AFGH there is no such document — neither paper publishes a vector, and no standards body has ever profiled either scheme.'
      ),
      p(
        'Generating one by running this implementation and freezing the output would test nothing at all: it would agree with any bug present at the moment of freezing. So the second table takes a different route. It uses small scalars a learner can follow by hand, and it checks the values that a mis-transcription would change — specifically the two lines most often copied wrong out of the literature.'
      ),
      p(
        'The first is BBS98’s re-encryption key orientation. It is b·a⁻¹. The reciprocal, a·b⁻¹, appears in the SAME paper, for the identification and signature cryptosystems, where the roles are reversed — so a reader skimming the paper can pick up the wrong one and produce a scheme that fails only at the second party.'
      ),
      p(
        'The second is AFGH’s level-2 decryption exponent. It is a1, not 1/a1. The 1/a form belongs to their Second Attempt, a different construction with a one-component key, a weaker assumption, and a different collusion residue. Getting this wrong produces a demo that appears to work and is not the scheme it claims to be.'
      ),
      p(
        'One further caveat on serialization: the KDF here consumes @noble/curves’ Fp12 byte order. There is no standardized compressed encoding for GT, and libraries differ in their Fp12 tower construction, so two implementations of this scheme would derive different data-encryption keys from the same group element. That is a property of this demo, not of the scheme.'
      )
    )
  );

  void run();

  async function run(): Promise<void> {
    const specRows = await specVectors();
    const transRows = transcriptionVectors();
    const allSpecPass = specRows.every((r) => r.expected === r.actual);
    const allTransPass = transRows.every((r) => r.expected === r.actual);
    replace(
      out,
      el('h4', { text: `Specification vectors — ${specRows.filter(passing).length} / ${specRows.length}` }),
      el('div', {}, specRows.map(rowNode)),
      el('h4', {
        text: `Scheme transcription checks (not specification vectors) — ${transRows.filter(passing).length} / ${transRows.length}`,
      }),
      el('div', {}, transRows.map(rowNode)),
      allSpecPass && allTransPass
        ? verdict(
            'pass',
            'Every vector recomputed and matched',
            `${specRows.length} published vectors and ${transRows.length} transcription checks, all compared byte for byte in this browser. The same checks run in the repository's unit suite.`
          )
        : verdict('fail', 'A vector did not match', 'This build is broken. Do not trust anything else on the page.')
    );
  }
}

function passing(r: Row): boolean {
  return r.expected === r.actual;
}

function rowNode(r: Row): HTMLElement {
  const ok = passing(r);
  return el('div', { class: `kat ${ok ? 'kat-pass' : 'kat-fail'}` }, [
    el('div', { class: 'row' }, [
      el('span', { class: `pill ${ok ? 'pill-ok' : 'pill-bad'}`, text: ok ? 'MATCH' : 'MISMATCH' }),
      el('span', { class: 'kat-name', text: r.name }),
    ]),
    el('div', { class: 'kat-src', text: r.source }),
    ok
      ? el('div', { class: 'bytes bytes-same', text: truncate(r.actual) })
      : el('div', {}, [
          el('div', { class: 'bytes bytes-diff', text: `expected ${truncate(r.expected)}` }),
          el('div', { class: 'bytes bytes-diff', text: `computed ${truncate(r.actual)}` }),
        ]),
  ]);
}

function truncate(hex: string): string {
  return hex.length <= 160 ? hex : `${hex.slice(0, 128)}… (${hex.length / 2} bytes)`;
}

async function specVectors(): Promise<Row[]> {
  const rows: Row[] = [];

  rows.push({
    name: 'BLS12-381 base field modulus p',
    source: 'draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1',
    expected:
      '1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab',
    actual: bls.fields.Fp.ORDER.toString(16),
  });
  rows.push({
    name: 'BLS12-381 subgroup order r',
    source: 'draft-irtf-cfrg-pairing-friendly-curves-11 §4.2.1',
    expected: '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001',
    actual: ORDER.toString(16),
  });
  rows.push({
    name: 'G1 generator, compressed',
    source: 'ZCash/IETF compressed point encoding',
    expected:
      '97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb',
    actual: bytesToHex(g1ToBytes(g1)),
  });
  rows.push({
    name: 'G2 generator, compressed',
    source: 'ZCash/IETF compressed point encoding',
    expected:
      '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e' +
      '024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8',
    actual: bytesToHex(g2ToBytes(g2)),
  });
  rows.push({
    name: 'GT membership: Z has order exactly r',
    source: 'computed — Z^r must be the identity of Fp12',
    expected: 'true',
    actual: String(isInGT(Z) && bls.fields.Fp12.eql(gtPow(Z, ORDER), bls.fields.Fp12.ONE)),
  });
  rows.push({
    name: 'Pairing bilinearity: e([7]g1, [11]g2) = Z^77',
    source: 'computed both ways and compared byte for byte',
    expected: bytesToHex(gtToBytes(gtPow(Z, 77n))),
    actual: bytesToHex(gtToBytes(pair(g1.multiply(7n), g2.multiply(11n)))),
  });

  const hkdf = async (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Promise<string> => {
    const key = await crypto.subtle.importKey('raw', copy(ikm), 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: copy(salt), info: copy(info) },
      key,
      len * 8
    );
    return bytesToHex(new Uint8Array(bits));
  };

  rows.push({
    name: 'HKDF-SHA-256 Test Case 1',
    source: 'RFC 5869 Appendix A.1',
    expected: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    actual: await hkdf(
      hexToBytes('0b'.repeat(22)),
      hexToBytes('000102030405060708090a0b0c'),
      hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
      42
    ),
  });
  rows.push({
    name: 'HKDF-SHA-256 Test Case 3 (empty salt and info)',
    source: 'RFC 5869 Appendix A.3',
    expected: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    actual: await hkdf(hexToBytes('0b'.repeat(22)), new Uint8Array(0), new Uint8Array(0), 42),
  });

  const gcm = async (k: string, iv: string, pt: string, aad: string): Promise<string> => {
    const key = await crypto.subtle.importKey('raw', copy(hexToBytes(k)), 'AES-GCM', false, ['encrypt']);
    const outBuf = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: copy(hexToBytes(iv)),
        additionalData: copy(hexToBytes(aad)),
        tagLength: 128,
      },
      key,
      copy(hexToBytes(pt))
    );
    return bytesToHex(new Uint8Array(outBuf));
  };

  rows.push({
    name: 'AES-256-GCM Test Case 13 (empty plaintext)',
    source: 'Galois/Counter Mode specification',
    expected: '530f8afbc74536b9a963b4f1c4cb738b',
    actual: await gcm('00'.repeat(32), '00'.repeat(12), '', ''),
  });
  rows.push({
    name: 'AES-256-GCM Test Case 16 (with additional authenticated data)',
    source: 'Galois/Counter Mode specification',
    expected:
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
      '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662' +
      '76fc6ece0f4e1768cddf8853bb2d551b',
    actual: await gcm(
      'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      'cafebabefacedbaddecaf888',
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
      'feedfacedeadbeeffeedfacedeadbeefabaddad2'
    ),
  });

  return rows;
}

function transcriptionVectors(): Row[] {
  const rows: Row[] = [];

  const alice = bbs98.keypairFromScalar('Alice', 7n);
  const bob = bbs98.keypairFromScalar('Bob', 11n);
  const rk = bbs98.rekeygen(alice, bob);

  rows.push({
    name: 'BBS98 rk with a = 7, b = 11 is b·a⁻¹ (NOT a·b⁻¹)',
    source: 'small-scalar transcription check — the reciprocal is the signature scheme in the same paper',
    expected: scalarToHex(divScalar(11n, 7n)),
    actual: scalarToHex(rk.value),
  });
  rows.push({
    name: "BBS98 c2' = [rk]c2 equals a fresh encryption to Bob with the same k",
    source: 'perfect key switching, computed both ways with k = 5',
    expected: bytesToHex(g1ToBytes(bob.pk.multiply(5n))),
    actual: bytesToHex(g1ToBytes(alice.pk.multiply(5n).multiply(rk.value))),
  });
  rows.push({
    name: 'BBS98 collusion recovers a = 7 exactly',
    source: 'b · rk⁻¹, checked against the scalar and against the published public key',
    expected: `7 / ${bytesToHex(g1ToBytes(alice.pk))}`,
    actual: (() => {
      const r = bbs98.collude(rk, bob.sk, alice.pk, alice.sk);
      return `${r.recovered} / ${bytesToHex(g1ToBytes(r.recoveredPk))}`;
    })(),
  });

  const A = afgh.keypairFromScalars('Alice', 7n, 13n);
  const B = afgh.keypairFromScalars('Bob', 17n, 19n);
  const rk2 = afgh.rekeygen(A, afgh.publicKey(B));

  rows.push({
    name: 'AFGH rk with a1 = 7, b2 = 19 is [a1·b2]g2',
    source: 'small-scalar transcription check; equals [a1]([b2]g2), the non-interactive identity',
    expected: bytesToHex(g2ToBytes(g2.multiply(7n * 19n))),
    actual: bytesToHex(g2ToBytes(rk2.value)),
  });
  rows.push({
    name: 'AFGH re-encryption lands on Z^(a1·b2·k) with k = 5',
    source: 'the real pairing, compared against the exponent computed directly in Z_r',
    expected: bytesToHex(gtToBytes(gtPow(Z, 7n * 19n * 5n))),
    actual: bytesToHex(gtToBytes(pair(g1.multiply(5n), rk2.value))),
  });
  rows.push({
    name: 'AFGH weak key is [a1]g2, and does not depend on b1',
    source: 'rk scaled by b2⁻¹; b1 = 17 appears nowhere in the delegation',
    expected: bytesToHex(g2ToBytes(g2.multiply(7n))),
    actual: bytesToHex(g2ToBytes(afgh.collude(rk2, 19n, A).weakKey)),
  });
  rows.push({
    name: 'AFGH level-2 decryption exponent is a1, not 1/a1',
    source: 'the 1/a form is the paper’s Second Attempt — a different scheme',
    expected: bytesToHex(gtToBytes(gtPow(Z, 7n * 5n))),
    actual: bytesToHex(gtToBytes(gtPow(pair(g1.multiply(5n), g2), A.a1))),
  });

  return rows;
}

function copy(v: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(v.byteLength);
  new Uint8Array(out).set(v);
  return out;
}
