import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import {
  bytesToHex,
  g1ToBytes,
  g2,
  g2ToBytes,
  invScalar,
  mulScalar,
  scalarToHex,
} from '../crypto/group';
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
  tableWrap,
  verdict,
} from './dom';
import type { Lab } from './lab';

/**
 * Acts 2 and 3 — the collusion, and the fix.
 *
 * This is the panel the brief is built around, and it is the one where honesty
 * costs the most, so it is worth being exact about what each half shows.
 *
 * Under BBS98 the outcome really is total. rk is the scalar b·a⁻¹; Bob knows b;
 * b ÷ rk is a. The page runs that division and then checks the result two
 * independent ways — against Alice's actual scalar, and by recomputing [a]g and
 * comparing it against her PUBLISHED public key, a value the collusion never
 * touched. Then it uses the recovered key on a ciphertext created after the
 * fact, because "recovered the key" and "can read her mail forever" are
 * different claims and only the second one matters.
 *
 * Under AFGH the outcome is NOT "nothing". The brief said "nothing usable
 * emerges" and that is overstated relative to the paper. AFGH themselves write:
 * "If Bob and the proxy collude, they cannot decrypt first-level encryptions
 * intended for Alice. Indeed, they can recover only the weak secret g^{a1} that
 * can only be used to decrypt second-level encryptions (which Bob and the proxy
 * can already open anyway)." Their comparison table scores collusion-safety
 * "Yes*", footnoted "* indicates master secret key only". So this panel shows
 * the weak key being recovered, shows it opening a level-2 ciphertext, and only
 * then shows what it cannot do. Rounding that up to "nothing emerges" would
 * teach something false, which the pedagogy standard forbids more strictly than
 * it demands a tidy story.
 */

export function renderCollusion(lab: Lab, host: HTMLElement): void {
  const out = liveRegion('Collusion result');
  const followUp = el('div');

  const bCollude = button('Run the collusion', () => void collude(), { class: 'btn-danger' });
  const bUse = button('Now use what they recovered', () => void useIt(), { disabled: true });
  const bSurvive = button('What survives?', () => void survives(), { disabled: true });

  const setup = card();
  setup.appendChild(kicker('Act 2 — Collusion'));
  setup.appendChild(h3('The proxy and the delegatee compare notes'));
  setup.appendChild(
    p(
      'A proxy is semi-trusted, not trusted: the whole premise is that it might misbehave. So assume the worst realistic thing — the relay and the person it was relaying to talk to each other. Each of them holds exactly one value they were supposed to hold. What can they build from the pair?'
    )
  );
  const inputs = el('div', { class: 'grid-2' });
  setup.appendChild(inputs);
  setup.appendChild(
    el('div', { class: 'row', role: 'group', 'aria-label': 'Collusion controls' }, [
      bCollude,
      bUse,
      bSurvive,
    ])
  );
  host.appendChild(setup);

  const results = card();
  results.appendChild(kicker('Result'));
  results.appendChild(out);
  results.appendChild(followUp);
  host.appendChild(results);

  host.appendChild(comparisonCard());
  host.appendChild(
    callout(
      'scope',
      el('strong', { text: 'What this does not prove. ' }),
      'That BBS98 falls to collusion is a demonstration; that AFGH does not is only demonstrated for the specific attacks run here. AFGH prove master-secret security by reduction to the discrete logarithm problem in their Theorem 3.1 — this page cannot reproduce a reduction, only show that the obvious attack has no analogue and that the residue is bounded to the capability already delegated.'
    )
  );

  function renderInputs(): void {
    replace(inputs);
    if (lab.scheme === 'bbs98') {
      const rk = bbs98.rekeygen(lab.bbs('Alice'), lab.bbs('Bob'));
      inputs.appendChild(
        el('div', {}, [
          el('h4', { text: 'The proxy holds' }),
          byteField('rk = b · a⁻¹  (a scalar mod r)', scalarToHex(rk.value)),
        ])
      );
      inputs.appendChild(
        el('div', {}, [
          el('h4', { text: 'Bob holds' }),
          byteField('his own private key b', scalarToHex(lab.bbs('Bob').sk)),
        ])
      );
    } else {
      const rk = afgh.rekeygen(lab.afgh('Alice'), afgh.publicKey(lab.afgh('Bob')));
      inputs.appendChild(
        el('div', {}, [
          el('h4', { text: 'The proxy holds' }),
          byteField('rk = g2^(a1 · b2)  (a POINT in G2)', bytesToHex(g2ToBytes(rk.value))),
        ])
      );
      inputs.appendChild(
        el('div', {}, [
          el('h4', { text: 'Bob holds' }),
          byteField('his delegation-acceptance secret b2', scalarToHex(lab.afgh('Bob').a2)),
        ])
      );
    }
  }

  async function collude(): Promise<void> {
    replace(followUp);
    if (lab.scheme === 'bbs98') {
      const alice = lab.bbs('Alice');
      const bob = lab.bbs('Bob');
      const rk = bbs98.rekeygen(alice, bob);
      const r = bbs98.collude(rk, bob.sk, alice.pk, alice.sk);
      const arith = el('div', { class: 'ledger' }, [
        el('div', { class: 'ledger-label', text: 'they compute' }),
        el('div', { class: 'ledger-expr' }, [
          el('span', { class: 'tok tok-b', text: 'b' }),
          el('span', { class: 'tok tok-op', text: '÷' }),
          el('span', { class: 'tok tok-k', text: 'rk' }),
          el('span', { class: 'tok tok-op', text: '=' }),
          el('span', { class: 'tok tok-b', text: 'b' }),
          el('span', { class: 'tok tok-op', text: '÷' }),
          el('span', { class: 'tok tok-op', text: '(' }),
          el('span', { class: 'tok tok-b', text: 'b' }),
          el('span', { class: 'tok tok-op', text: '/' }),
          el('span', { class: 'tok tok-a', text: 'a' }),
          el('span', { class: 'tok tok-op', text: ')' }),
          el('span', { class: 'tok tok-op', text: '=' }),
          el('span', { class: 'tok tok-a tok-arrive', text: 'a' }),
        ]),
      ]);
      replace(
        out,
        arith,
        // `breach`, not `same`: these two matching is the worst outcome on the
        // page, and a green badge here would read as a pass.
        byteField('recovered scalar', scalarToHex(r.recovered), r.exact ? 'breach' : 'diff'),
        byteField('Alice’s actual private key a', scalarToHex(alice.sk), r.exact ? 'breach' : 'diff'),
        byteField(
          '[recovered] · g, recomputed',
          bytesToHex(g1ToBytes(r.recoveredPk)),
          r.matchesPublicKey ? 'breach' : 'diff'
        ),
        byteField(
          'Alice’s PUBLISHED public key',
          bytesToHex(g1ToBytes(alice.pk)),
          r.matchesPublicKey ? 'breach' : 'diff'
        ),
        verdict(
          r.exact ? 'alarm' : 'pass',
          r.exact ? 'Alice’s private key is on the table' : 'No key recovered',
          r.exact
            ? 'One modular division. No cryptanalysis, no search, no assumption weakened. The recovered scalar is compared against Alice’s actual key AND, independently, its public key is recomputed and compared against the one Alice published — a value nothing in the collusion touched.'
            : 'Unexpected for BBS98 — please report.',
          r.exact ? 'COLLUSION_KEY_RECOVERED' : undefined
        )
      );
      bUse.disabled = false;
      bSurvive.disabled = false;
      return;
    }

    // AFGH
    const alice = lab.afgh('Alice');
    const bob = lab.afgh('Bob');
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const r = afgh.collude(rk, bob.a2, alice);
    const naive = mulScalar(bob.a2, invScalar(bob.a2));
    const arith = el('div', { class: 'ledger' }, [
      el('div', { class: 'ledger-label', text: 'the BBS98 move' }),
      el('div', { class: 'ledger-expr' }, [
        el('span', { class: 'tok tok-b', text: 'b2' }),
        el('span', { class: 'tok tok-op', text: '÷' }),
        el('span', { class: 'tok tok-k', text: 'rk' }),
        el('span', { class: 'hint', text: 'undefined — rk is a point, not a number. There is no division to perform.' }),
      ]),
      el('div', { class: 'ledger-label', text: 'what they CAN do' }),
      el('div', { class: 'ledger-expr' }, [
        el('span', { class: 'tok tok-k', text: 'rk' }),
        el('span', { class: 'tok tok-op', text: 'scaled by' }),
        el('span', { class: 'tok tok-b', text: 'b2⁻¹' }),
        el('span', { class: 'tok tok-op', text: '=' }),
        el('span', { class: 'tok tok-plain', text: 'g2' }),
        el('span', { class: 'tok tok-op', text: '^' }),
        el('span', { class: 'tok tok-a tok-arrive', text: 'a1' }),
      ]),
    ]);
    replace(
      out,
      arith,
      // `bounded`: a real loss, but not the master secret — amber, not red.
      byteField('recovered weak key', bytesToHex(g2ToBytes(r.weakKey)), r.weakKeyMatches ? 'bounded' : 'diff'),
      byteField(
        'g2^a1, recomputed from Alice’s secret',
        bytesToHex(g2ToBytes(g2.multiply(alice.a1))),
        r.weakKeyMatches ? 'bounded' : 'diff'
      ),
      verdict(
        'caution',
        'The master secret survived — but something real did leak',
        `They cannot divide their way to a1: getting a1 out of g2^a1 is a discrete logarithm in G2. What they do get is g2^a1 itself, AFGH's "weak" secret. That is a genuine, permanent, transferable capability, and the next button uses it. (The naive scalar move ${naive === 1n ? 'collapses to 1' : 'produces nothing'}, which is the point: Bob can only cancel the part he contributed.)`
      )
    );
    bUse.disabled = false;
    bSurvive.disabled = false;
  }

  async function useIt(): Promise<void> {
    if (lab.scheme === 'bbs98') {
      const alice = lab.bbs('Alice');
      const bob = lab.bbs('Bob');
      const rk = bbs98.rekeygen(alice, bob);
      const { recovered } = bbs98.collude(rk, bob.sk, alice.pk, alice.sk);
      const secret = 'A message Alice sent long after that delegation, to somebody else entirely.';
      const later = await bbs98.encrypt(alice, secret);
      const got = await bbs98.decrypt(bbs98.keypairFromScalar('impostor', recovered), later);
      replace(
        followUp,
        el('h4', { text: 'A message encrypted AFTER the collusion, never sent to the proxy' }),
        el('div', { class: `bytes ${got === secret ? 'bytes-breach' : ''}`, text: got ?? '(could not decrypt)' }),
        verdict(
          got === secret ? 'alarm' : 'pass',
          got === secret ? 'Read in full, with no proxy involved' : 'Not readable',
          got === secret
            ? 'Recovering a is not "they can read the delegated file". It is every ciphertext ever sent to Alice, past and future; the ability to mint re-encryption keys from Alice to anyone; and whatever else that key is used for, including signing if she reuses it. Deleting the re-encryption key from the proxy changes none of this.'
            : 'Unexpected — please report.',
          got === secret ? 'COLLUSION_KEY_RECOVERED' : undefined
        )
      );
      return;
    }
    const alice = lab.afgh('Alice');
    const bob = lab.afgh('Bob');
    const rk = afgh.rekeygen(alice, afgh.publicKey(bob));
    const { weakKey } = afgh.collude(rk, bob.a2, alice);
    const secret = 'A level-2 message Alice wrote after the delegation, still stored on the server.';
    const later = await afgh.encryptLevel2(afgh.publicKey(alice), secret);
    const got = await afgh.decryptWithWeakKey(weakKey, later);
    replace(
      followUp,
      el('h4', { text: 'A level-2 ciphertext, opened with the weak key alone' }),
      el('div', { class: `bytes ${got === secret ? 'bytes-bounded' : ''}`, text: got ?? '(could not decrypt)' }),
      verdict(
        'caution',
        got === secret ? 'Opened — and this is the honest half of the story' : 'Not readable',
        got === secret
          ? 'g2^a1 opens every level-2 ciphertext under Alice’s key, forever, offline, with no proxy in the loop. AFGH’s defence is precise: this is not a NEW capability, because opening Alice’s level-2 ciphertexts is exactly what delegating to Bob already authorised. What changed is that it no longer needs the proxy — which is why deleting the re-encryption key revokes nothing. That is the Un-delegate tab.'
          : 'Unexpected — please report.'
      )
    );
  }

  async function survives(): Promise<void> {
    if (lab.scheme === 'bbs98') {
      replace(
        followUp,
        verdict(
          'alarm',
          'Nothing survives',
          'There is one secret in BBS98 and the colluders have it. There is no second key protecting anything, no level structure, and no ciphertext Alice can hold that the recovered scalar does not open. This is why the scheme is described as requiring bilateral unconditional trust: the paper says so itself — "A and B must trust one another bilaterally."',
          'COLLUSION_KEY_RECOVERED'
        )
      );
      return;
    }
    const alice = lab.afgh('Alice');
    const bob = lab.afgh('Bob');
    const priv = await afgh.encryptLevel1(afgh.publicKey(alice), 'Alice’s private mail, addressed to nobody else.', 1);
    const guesses: { label: string; value: bigint }[] = [
      { label: 'Bob’s a1', value: bob.a1 },
      { label: 'Bob’s b2', value: bob.a2 },
      { label: 'a1 · b2 (the exponent inside rk)', value: mulScalar(alice.a1, bob.a2) },
    ];
    const rows: HTMLElement[] = [];
    for (const g of guesses) {
      const got = await afgh.attemptLevel1WithScalar(priv, g.value);
      rows.push(
        el('tr', {}, [
          el('td', { text: g.label }),
          el('td', { class: 'mono', text: got === null ? 'rejected' : got }),
        ])
      );
    }
    const truth = await afgh.attemptLevel1WithScalar(priv, alice.a1);
    replace(
      followUp,
      el('h4', { text: 'A level-1 ciphertext addressed to Alice, attacked with everything the colluders have' }),
      tableWrap(
        'Scalars tried against a level-1 ciphertext, scrollable',
        el('table', { class: 'guess-table' }, [
          el('caption', { text: 'Every scalar the colluders can form, run through the real level-1 decryptor' }),
          el('thead', {}, [
            el('tr', {}, [el('th', { text: 'scalar tried' }), el('th', { text: 'result' })]),
          ]),
          el('tbody', {}, rows),
        ])
      ),
      verdict(
        'pass',
        'Alice’s private mail is untouched',
        `The weak key g2^a1 cannot even be APPLIED here: alpha lives in GT, and no pairing consumes a GT element. All that is left is guessing the scalar, and only the true a1 works — which is the discrete logarithm the colluders are stuck behind. (Confirmed: with a1 the same ciphertext reads "${truth ?? 'FAILED'}".)`
      ),
      callout(
        'caveat',
        el('strong', { text: 'And the part that matters outside this page: ' }),
        'a1 is also Alice’s signing key if she uses this key pair for signatures. AFGH make that argument explicitly — because Schnorr and ElGamal signatures are proofs of knowledge of the discrete log, master-secret security means a user "may be able to safely delegate decryption rights without delegating signing rights for the same public key." Under BBS98 she loses both at once.'
      )
    );
  }

  function comparisonCard(): HTMLElement {
    const c = card();
    c.appendChild(kicker('Act 3 — The fix'));
    c.appendChild(h3('Why one scheme falls and the other does not'));
    c.appendChild(
      p(
        'It comes down to one thing: WHERE the re-encryption key lives. BBS98 puts it in the scalar field, where inversion is public and anyone can do it. AFGH puts Alice’s secret in an EXPONENT, behind a discrete logarithm, and Bob’s contribution in a public group element. Bob can cancel the part he contributed. He cannot cancel the part he never had.'
      )
    );
    c.appendChild(
      tableWrap(
        'BBS98 and AFGH compared, scrollable',
        el('table', {}, [
          el('caption', {
            text: 'Side by side. Rows marked "shown here" are demonstrated by the buttons above, not asserted.',
          }),
          el('thead', {}, [
            el('tr', {}, [
              el('th', { text: '' }),
              el('th', { text: 'BBS98 (1998)' }),
              el('th', { text: 'AFGH (2005)' }),
            ]),
          ]),
          el('tbody', {}, [
            trow('re-encryption key is', 'a scalar b·a⁻¹ mod r', 'a point g2^(a1·b2) in G2'),
            trow('to build it you need', 'BOTH private keys (interactive)', 'the delegator’s secret and the delegatee’s PUBLIC key'),
            trow('direction', 'bidirectional — invert rk and it runs backwards', 'unidirectional — the reverse key is a different pair of exponents'),
            trow('hops', 'unbounded, and transitive: rk(A→B)·rk(B→C) = rk(A→C)', 'exactly one, by construction'),
            trow('collusion yields — shown here', 'the delegator’s full private key a', 'the weak key g2^a1 only'),
            trow('what that opens — shown here', 'everything, forever, including future ciphertexts', 'level-2 ciphertexts only — the capability already delegated'),
            trow('what survives — shown here', 'nothing', 'the master secret a1, and every level-1 ciphertext'),
            trow('revocation', 'none', 'none in this construction — see the Un-delegate tab'),
          ]),
        ])
      )
    );
    c.appendChild(
      details(
        'The exact wording from the AFGH paper, because this is easy to overstate',
        p(
          'AFGH state the property as: "One drawback of all previous schemes is that by colluding, Bob and the proxy can recover Alice’s secret key: for Dodis-Ivan, s = s1 + s2; for BBS, a = (a/b)·b. We will mitigate this problem — allowing recovery of a ‘weak’ secret key only."'
        ),
        p(
          'And for this particular construction: "If Bob and the proxy collude, they cannot decrypt first-level encryptions intended for Alice. Indeed, they can recover only the weak secret g^{a1} that can only be used to decrypt second-level encryptions (which Bob and the proxy can already open anyway)."'
        ),
        p(
          'Their comparison table scores collusion-safety for this scheme as "Yes", with the footnote "indicates master secret key only". Mitigate, not eliminate. This page follows that wording rather than improving on it.'
        ),
        p(
          'One more thing the same paper is careful about, and which this page repeats on the Un-delegate tab: NO scheme in their table achieves non-transferability. Once the colluders hold g2^a1 they can hand it to anyone.'
        )
      )
    );
    return c;
  }

  renderInputs();
}

function trow(label: string, a: string, b: string): HTMLTableRowElement {
  return el('tr', {}, [
    el('th', { scope: 'row', text: label }),
    el('td', { text: a }),
    el('td', { text: b }),
  ]);
}
