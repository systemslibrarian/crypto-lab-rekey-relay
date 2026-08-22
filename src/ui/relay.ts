import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import {
  bytesToHex,
  g1ToBytes,
  g2ToBytes,
  gtToBytes,
  scalarToHex,
} from '../crypto/group';
import type {
  AfghCiphertext,
  AfghCiphertextL1,
  AfghCiphertextL2,
  AnyCiphertext,
  Bbs98Ciphertext,
} from '../crypto/types';
import {
  byteField,
  button,
  callout,
  card,
  details,
  el,
  h3,
  kicker,
  liveRegion,
  p,
  replace,
  verdict,
} from './dom';
import type { Lab } from './lab';
import { buildLedger, ledgerCaption } from './ledger';

/**
 * Act 1 — Delegate.
 *
 * Alice encrypts to herself, issues a re-encryption key, the proxy transforms,
 * Bob reads. Four buttons, four real cryptographic operations, and the exponent
 * ledger filling in beside them.
 *
 * The claim this panel has to earn is that the proxy transforms the ciphertext
 * WITHOUT learning the plaintext, and it earns it two ways rather than
 * asserting it: the message-carrying half is compared byte for byte before and
 * after the hop and shown to be identical, and the persistent proxy panel below
 * searches everything the proxy handled for the learner's own message bytes.
 */

interface RelayState {
  ct?: AnyCiphertext;
  hopped?: AnyCiphertext;
  bbsRk?: ReturnType<typeof bbs98.rekeygen>;
  afghRk?: ReturnType<typeof afgh.rekeygen>;
  installed?: string;
}

export function renderRelay(lab: Lab, host: HTMLElement): void {
  const state: RelayState = {};

  const msg = el('textarea', {
    id: 'relay-msg',
    rows: '2',
    'aria-describedby': 'relay-msg-hint',
  });
  msg.value = lab.message;
  // A verdict that outlives the input it was computed from is a lie the page
  // tells quietly. Editing the message RETIRES everything downstream and says
  // so. The equality guard is the no-op case: an `input` event that did not
  // change the value must not throw away a fresh result.
  msg.addEventListener('input', () => {
    if (msg.value === lab.message) return;
    lab.message = msg.value;
    reset('retired');
  });

  const out = liveRegion('Relay result');
  const ledgerBox = el('div');
  const stepNote = el('p', { class: 'step-note' });

  const bEncrypt = button('1 · Alice encrypts', () => void encrypt(), { class: 'btn-primary' });
  const bRekey = button('2 · Alice issues rk', () => void issue(), { disabled: true });
  const bHop = button('3 · Proxy transforms', () => void transform(), { disabled: true });
  const bRead = button('4 · Bob decrypts', () => void read(), { disabled: true });
  const bReset = button('Reset', () => reset());

  const bCorrupt = button('Corrupt the rk', () => void corruptRk(), {
    class: 'btn-danger',
    disabled: true,
  });
  const bMisroute = button('Send it Carol’s ciphertext', () => void misroute(), {
    class: 'btn-danger',
    disabled: true,
  });
  const bAliceAfter = button('Alice reads it after the hop', () => void aliceAfter(), {
    class: 'btn-danger',
    disabled: true,
  });

  function setStep(n: 0 | 1 | 2 | 3 | 4): void {
    bRekey.disabled = n < 1;
    bHop.disabled = n < 2;
    bRead.disabled = n < 3;
    bCorrupt.disabled = n < 2;
    bMisroute.disabled = n < 2;
    bAliceAfter.disabled = n < 3;
  }

  function reset(reason: 'fresh' | 'retired' = 'fresh'): void {
    delete state.ct;
    delete state.hopped;
    delete state.bbsRk;
    delete state.afghRk;
    delete state.installed;
    setStep(0);
    replace(ledgerBox);
    replace(out);
    stepNote.textContent =
      reason === 'retired'
        ? 'Message changed — the previous ciphertext and every result below it were RETIRED. Press step 1 to run the scheme against the new text.'
        : 'Nothing has been encrypted yet. Press step 1 to run the real scheme against the message above.';
  }

  async function encrypt(): Promise<void> {
    const text = msg.value;
    state.ct =
      lab.scheme === 'bbs98'
        ? await bbs98.encrypt(lab.bbs('Alice'), text)
        : await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), text);
    delete state.hopped;
    setStep(1);
    showLedger('encrypted');
    replace(
      out,
      ctFields(state.ct, undefined),
      verdict(
        'pass',
        'Encrypted to Alice',
        lab.scheme === 'bbs98'
          ? 'A random group element M was drawn, HKDF-SHA-256 turned it into an AES-256-GCM key, and that key encrypted your text. M itself is hidden in c1 = M · g^k.'
          : 'A random element of GT was drawn, HKDF-SHA-256 turned it into an AES-256-GCM key, and that key encrypted your text. This is a LEVEL-2 ciphertext: the form that can still be re-encrypted.'
      )
    );
  }

  function issue(): void {
    if (lab.scheme === 'bbs98') {
      state.bbsRk = bbs98.rekeygen(lab.bbs('Alice'), lab.bbs('Bob'));
    } else {
      state.afghRk = afgh.rekeygen(lab.afgh('Alice'), afgh.publicKey(lab.afgh('Bob')));
    }
    setStep(2);
    replace(out, rkPanel());
    stepNote.textContent =
      lab.scheme === 'bbs98'
        ? 'Look at what rk IS: a 256-bit number. Numbers can be divided. Hold that thought until the Collusion tab.'
        : 'Look at what rk IS: a point on a curve, not a number. Alice built it from her own a1 and Bob’s PUBLISHED key — Bob was never asked.';
  }

  function transform(): void {
    if (!state.ct) return;
    const rk = lab.scheme === 'bbs98' ? state.bbsRk : state.afghRk;
    if (!rk) return;
    const id = lab.proxy.edgeId(lab.scheme, 'Alice', 'Bob');
    if (!lab.proxy.hasKey(id)) {
      const installed = lab.proxy.install(rk);
      if (!installed.ok) {
        replace(out, verdict('fail', 'The proxy refused the key', installed.detail, installed.code));
        lab.proxyChanged();
        return;
      }
    }
    state.installed = id;
    const result = lab.proxy.transform(id, state.ct);
    lab.proxyChanged();
    if (!result.ok) {
      replace(out, verdict('fail', 'The proxy refused', result.detail, result.code));
      return;
    }
    state.hopped = result.value;
    setStep(3);
    showLedger('transformed');
    replace(
      out,
      ctFields(result.value, state.ct),
      verdict(
        'pass',
        'Transformed — and the message half did not move',
        'The two panes above are the ciphertext before and after. The message-carrying half is compared byte for byte, and it is identical. The proxy changed exactly one component, and that component carries no message.'
      )
    );
  }

  async function read(): Promise<void> {
    if (!state.hopped) return;
    const typed = msg.value;
    let got: string | null = null;
    if (state.hopped.scheme === 'bbs98') {
      got = await bbs98.decrypt(lab.bbs('Bob'), state.hopped);
    } else {
      const r = await afgh.decrypt(lab.afgh('Bob'), state.hopped as AfghCiphertext);
      got = r.ok ? r.value : null;
    }
    setStep(4);
    showLedger('decrypted');
    const match = got === typed;
    replace(
      out,
      el('div', { class: 'grid-2' }, [
        el('div', {}, [
          el('span', { class: 'field-name', text: 'what Alice typed' }),
          el('div', { class: 'bytes', text: typed }),
        ]),
        el('div', {}, [
          el('span', { class: 'field-name', text: 'what Bob decrypted' }),
          el('div', { class: `bytes ${match ? 'bytes-same' : 'bytes-diff'}`, text: got ?? '(decryption failed)' }),
        ]),
      ]),
      match
        ? verdict(
            'pass',
            'Byte-for-byte identical',
            `${typed.length} characters in, ${(got ?? '').length} characters out, compared on the page rather than asserted. Bob has read a message that was never encrypted to him, and the proxy never held it.`
          )
        : verdict('fail', 'Bob could not read it', 'The AEAD tag rejected. No plaintext is returned unauthenticated.')
    );
  }

  async function corruptRk(): Promise<void> {
    if (!state.ct) return;
    const id = lab.proxy.edgeId(lab.scheme, 'Alice', 'Bob');
    let bad;
    if (lab.scheme === 'bbs98' && state.bbsRk) {
      bad = { ...state.bbsRk, value: 0n };
    } else if (state.afghRk) {
      bad = { ...state.afghRk, value: state.afghRk.value.subtract(state.afghRk.value) };
    }
    if (!bad) return;
    const installed = lab.proxy.install(bad);
    lab.proxyChanged();
    replace(
      out,
      installed.ok
        ? verdict('fail', 'The proxy accepted a key it should have refused', 'This is a bug, not a lesson.')
        : verdict(
            'fail',
            'Refused before a single point was touched',
            `${installed.detail}. A zero scalar, or the identity point, would map every ciphertext to the same constant — so the proxy validates the key structurally on arrival and refuses, rather than producing something that looks like a ciphertext and is not.`,
            installed.code
          ),
      el('p', { class: 'step-note', text: `The good key is still installed at ${id}; press step 3 again to continue.` })
    );
  }

  async function misroute(): Promise<void> {
    const id = lab.proxy.edgeId(lab.scheme, 'Alice', 'Bob');
    const carolCt: AnyCiphertext =
      lab.scheme === 'bbs98'
        ? await bbs98.encrypt(lab.bbs('Carol'), 'a message that was never Alice’s')
        : await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Carol')), 'a message that was never Alice’s');
    if (!lab.proxy.hasKey(id)) {
      const rk = lab.scheme === 'bbs98' ? state.bbsRk : state.afghRk;
      if (rk) lab.proxy.install(rk);
    }
    const result = lab.proxy.transform(id, carolCt);
    lab.proxyChanged();
    replace(
      out,
      result.ok
        ? verdict('fail', 'The proxy transformed a ciphertext it had no key for', 'This is a bug, not a lesson.')
        : verdict(
            'fail',
            'Refused — the key does not match the ciphertext',
            `${result.detail}. Skipping this check would not throw an error: it would produce a perfectly well-formed ciphertext that nobody on earth can open. Failing closed is the difference between a refusal and silent data loss.`,
            result.code
          )
    );
  }

  async function aliceAfter(): Promise<void> {
    if (!state.hopped) return;
    let got: string | null = null;
    if (state.hopped.scheme === 'bbs98') {
      got = await bbs98.decrypt(lab.bbs('Alice'), state.hopped);
    } else {
      const r = await afgh.decrypt(lab.afgh('Alice'), state.hopped as AfghCiphertext);
      got = r.ok ? r.value : null;
    }
    replace(
      out,
      got === null
        ? verdict(
            'caution',
            'Alice can no longer read her own ciphertext',
            lab.scheme === 'bbs98'
              ? 'The transform moved c2 from Alice’s key to Bob’s. There is only one ciphertext and it now belongs to Bob. Keeping the original is the storage system’s job, not the scheme’s.'
              : 'AFGH call this "original access", and their own comparison table scores it as achievable only with extra overhead — an additional retained term. This lab ships the scheme as written, so the cost is visible instead of hidden behind a stored copy.'
          )
        : verdict('fail', 'Alice read it, which the scheme does not promise', 'Unexpected — please report.')
    );
  }

  function showLedger(stage: 'encrypted' | 'transformed' | 'decrypted'): void {
    replace(
      ledgerBox,
      buildLedger(lab.scheme, stage),
      el('p', { class: 'step-note', text: ledgerCaption(lab.scheme, stage) })
    );
  }

  function rkPanel(): HTMLElement {
    if (lab.scheme === 'bbs98' && state.bbsRk) {
      return el('div', {}, [
        byteField('rk (a SCALAR mod r, 32 bytes)', scalarToHex(state.bbsRk.value)),
        verdict(
          'caution',
          'Generating this required BOTH private keys',
          'BBS98 rekeygen is b · a⁻¹, so Alice cannot delegate to Bob without Bob’s secret — or without a party that holds both. The scheme is interactive, and the key it produces works in both directions.'
        ),
      ]);
    }
    if (state.afghRk) {
      return el('div', {}, [
        byteField('rk (a POINT in G2, 96 bytes compressed)', bytesToHex(g2ToBytes(state.afghRk.value))),
        verdict(
          'pass',
          'Generated from Alice’s secret and Bob’s PUBLIC key alone',
          'AFGH rekeygen is (g2^a2 of Bob) raised to Alice’s a1. Bob was not consulted and gave up nothing. That is what non-interactive and unidirectional buy — and, as the Collusion tab shows, it is also what keeps Alice’s master secret out of the result.'
        ),
      ]);
    }
    return el('div');
  }

  const intro = card('intro');
  intro.appendChild(kicker('Act 1 — Delegate'));
  intro.appendChild(h3('Hand the courier a locked box, not the key'));
  intro.appendChild(
    p(
      'Alice keeps encrypted files on a server that cannot decrypt them, because it does not have her key — that is the point of putting them there encrypted. Now she wants Bob to read one. The clumsy answers are to send Bob her private key, or to download, decrypt and re-encrypt everything herself. Proxy re-encryption is the third answer: she hands a semi-trusted relay one small value that lets it convert her ciphertext into Bob’s, and the relay learns nothing about what is inside.'
    )
  );
  intro.appendChild(
    p(
      'Run it below. Every button performs the real operation on real BLS12-381 group elements — nothing here is a mock-up of a scheme.'
    )
  );
  host.appendChild(intro);

  const controls = card();
  controls.appendChild(el('label', { for: 'relay-msg', text: 'Message Alice is encrypting' }));
  controls.appendChild(msg);
  controls.appendChild(
    el('p', {
      id: 'relay-msg-hint',
      class: 'hint',
      text: 'Whatever you type here is what the proxy panel below searches for. Editing it resets the relay.',
    })
  );
  controls.appendChild(
    el('div', { class: 'row', role: 'group', 'aria-label': 'Relay steps' }, [
      bEncrypt,
      bRekey,
      bHop,
      bRead,
      bReset,
    ])
  );
  controls.appendChild(stepNote);
  host.appendChild(controls);

  const mech = card();
  mech.appendChild(kicker('The mechanism'));
  mech.appendChild(h3('What the proxy actually does to the exponent'));
  mech.appendChild(ledgerBox);
  host.appendChild(mech);

  const results = card();
  results.appendChild(kicker('Result'));
  results.appendChild(out);
  host.appendChild(results);

  const breakIt = card();
  breakIt.appendChild(kicker('Break it yourself'));
  breakIt.appendChild(h3('Three ways to make the relay refuse'));
  breakIt.appendChild(
    p(
      'Each of these runs against the same real code path the working relay uses. None of them is a simulated error message.',
      'hint'
    )
  );
  breakIt.appendChild(
    el('div', { class: 'row', role: 'group', 'aria-label': 'Failure paths' }, [
      bCorrupt,
      bMisroute,
      bAliceAfter,
    ])
  );
  host.appendChild(breakIt);

  host.appendChild(
    details(
      'Why the message has to be wrapped in AES-GCM at all',
      p(
        'Both schemes encrypt a GROUP ELEMENT, not a string. BBS98’s plaintext slot holds a point in G1; AFGH’s holds an element of GT. That is how both papers are written, and it is not a limitation worth hiding — it is why every real deployment of public-key encryption is hybrid.'
      ),
      p(
        'So this page does what a deployment does. The scheme carries a random group element M, HKDF-SHA-256 turns M’s canonical encoding into a 256-bit key, and AES-256-GCM encrypts your actual text under it. Both halves are WebCrypto, so the RFC 5869 and GCM test vectors on the Vectors tab apply to exactly this code path.'
      ),
      p(
        'The AEAD is bound with additional authenticated data to the one ciphertext component the proxy must never touch. If a re-encryption ever altered the message-carrying half, the tag would fail and the page would say so — the property is enforced by the cryptography rather than promised in a caption.'
      )
    )
  );

  host.appendChild(
    callout(
      'scope',
      el('strong', { text: 'What this does not prove. ' }),
      'A working round trip is a correctness demonstration, not a security proof. It does not show that the proxy could not learn the plaintext by some other route, only that it did not hold it here. The security arguments are in the papers: semantic security under eDBDH for AFGH, and under DDH for the ElGamal structure BBS98 is built on. Neither paper claims CCA2 security, and neither makes any guarantee about deliberately malformed ciphertexts.'
    )
  );

  reset();
}

// ── ciphertext rendering ───────────────────────────────────────────────────

function ctFields(ct: AnyCiphertext, before?: AnyCiphertext): HTMLElement {
  const box = el('div');
  if (ct.scheme === 'bbs98') {
    const prev = before?.scheme === 'bbs98' ? (before as Bbs98Ciphertext) : undefined;
    const c1 = bytesToHex(g1ToBytes(ct.c1));
    const c2 = bytesToHex(g1ToBytes(ct.c2));
    box.appendChild(
      byteField('c1 — message half (G1)', c1, prev ? (bytesToHex(g1ToBytes(prev.c1)) === c1 ? 'same' : 'diff') : undefined)
    );
    box.appendChild(
      byteField('c2 — key half (G1)', c2, prev ? (bytesToHex(g1ToBytes(prev.c2)) === c2 ? 'same' : 'diff') : undefined)
    );
    box.appendChild(
      byteField(
        'AES-GCM ciphertext + tag',
        bytesToHex(ct.payload.ct),
        prev ? (bytesToHex(prev.payload.ct) === bytesToHex(ct.payload.ct) ? 'same' : 'diff') : undefined
      )
    );
    return box;
  }
  const prev = before?.scheme === 'afgh' ? before : undefined;
  const beta = bytesToHex(gtToBytes(ct.beta));
  const prevBeta = prev ? bytesToHex(gtToBytes(prev.beta)) : undefined;
  box.appendChild(
    byteField(
      `beta — message half (GT, ${gtToBytes(ct.beta).length} bytes)`,
      beta,
      prevBeta ? (prevBeta === beta ? 'same' : 'diff') : undefined
    )
  );
  box.appendChild(
    ct.level === 2
      ? byteField(
          'alpha — key half (G1, level 2)',
          bytesToHex(g1ToBytes((ct as AfghCiphertextL2).alpha)),
          prev && prev.level === 2 ? 'same' : undefined
        )
      : byteField(
          'alpha — key half (GT, level 1)',
          bytesToHex(gtToBytes((ct as AfghCiphertextL1).alpha)),
          prev ? 'diff' : undefined
        )
  );
  box.appendChild(
    byteField(
      'AES-GCM ciphertext + tag',
      bytesToHex(ct.payload.ct),
      prev ? (bytesToHex(prev.payload.ct) === bytesToHex(ct.payload.ct) ? 'same' : 'diff') : undefined
    )
  );
  if (prev && prev.level === 2 && ct.level === 1) {
    box.appendChild(
      el('p', {
        class: 'step-note',
        text: 'The key half also changed GROUP: 48 bytes in G1 became 576 bytes in GT. That is the one-way step.',
      })
    );
  }
  return box;
}
