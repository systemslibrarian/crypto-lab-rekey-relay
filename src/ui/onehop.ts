import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import { scalarToHex } from '../crypto/group';
import type { AfghCiphertext, AnyCiphertext } from '../crypto/types';
import {
  button,
  callout,
  card,
  details,
  el,
  h3,
  kicker,
  liveRegion,
  list,
  p,
  replace,
  verdict,
} from './dom';
import type { Actor, Lab } from './lab';

/**
 * Act 4 — One hop only.
 *
 * Two schemes, one experiment: relay the same ciphertext down a chain
 * Alice to Bob to Carol to Dave, and watch where it stops.
 *
 * BBS98 never stops. A re-encrypted BBS98 ciphertext is the same shape as a
 * fresh one — one ciphertext space, one decryption algorithm — so it hops
 * forever at constant size. It is also transitive, which is worse than it
 * sounds: the proxy can MULTIPLY two re-encryption keys together and mint a
 * third that nobody issued. Blaze, Bleumer and Strauss say so themselves:
 * "The proxy relationship is necessarily transitive. If there are public proxy
 * keys pi_{A->B} and pi_{B->C}, then anyone can compute a proxy function for
 * A->C."
 *
 * AFGH stops after one hop, and not because a rule in this codebase says so.
 * A level-2 ciphertext's key half is in G1, a pairing INPUT group; after the
 * transform it is in GT, the pairing OUTPUT group; and no pairing consumes a GT
 * element. The `ALREADY_REENCRYPTED` branch exists to NAME an impossibility,
 * not to prevent something otherwise possible. That is the difference between
 * single-hop by construction and single-hop by agreement.
 */

const CHAIN: Actor[] = ['Alice', 'Bob', 'Carol', 'Dave'];

export function renderOneHop(lab: Lab, host: HTMLElement): void {
  const out = liveRegion('Chain result');

  const bChain = button('Relay it down the chain', () => void runChain(), { class: 'btn-primary' });
  const bCompose = button('Let the proxy mint a key nobody issued', () => void compose(), {});
  const bWrongLevel = button('Decrypt at the wrong level', () => void wrongLevel(), {
    class: 'btn-danger',
  });

  const intro = card('intro');
  intro.appendChild(kicker('Act 4 — One hop only'));
  intro.appendChild(h3('How far can a delegated ciphertext travel?'));
  intro.appendChild(
    p(
      'Delegation looks harmless one step at a time. The question is what happens on step two. If Bob can delegate onward to Carol using the same relay, then Alice’s one decision has produced a chain she never approved and cannot see the end of.'
    )
  );
  intro.appendChild(
    p(
      'Run the same ciphertext down Alice → Bob → Carol → Dave under each scheme. The result is not a matter of policy in either case; it falls out of what group the ciphertext is sitting in.'
    )
  );
  host.appendChild(intro);

  const controls = card();
  controls.appendChild(
    el('div', { class: 'row', role: 'group', 'aria-label': 'Chain controls' }, [
      bChain,
      bCompose,
      bWrongLevel,
    ])
  );
  controls.appendChild(out);
  host.appendChild(controls);

  host.appendChild(
    details(
      'Why AFGH cannot take a second hop, in one paragraph',
      p(
        'Re-encryption IS the pairing. The proxy computes e(alpha, rk), and a pairing is defined on G1 × G2 — it takes two source-group elements and produces a target-group element. After one transform, alpha is a target-group element. There is no map out of the target group and no pairing that accepts one as an argument, so there is nothing left to compute. The ciphertext has spent its one available pairing.'
      ),
      p(
        'A second, independent reason: the original randomness is gone. After the hop the ciphertext is (Z^(b2·k′), M·Z^(k′)) with k′ = a1·k, and there is no g1^something left in it for a re-encryption key to act on. Even a hypothetical GT-consuming map would have nothing structured to grab.'
      ),
      p(
        'A note on vocabulary: AFGH never write "single-hop" or "multi-hop" — those terms come from later work (Canetti and Hohenberger 2007; Libert and Vergnaud 2008). AFGH record the limitation as an open problem in their conclusion: "Another challenging problem is to find unidirectional re-encryption schemes that allow ciphertexts to be re-encrypted in sequence and multiple times."'
      )
    )
  );

  host.appendChild(
    callout(
      'caveat',
      el('strong', { text: 'Neither answer is simply better. ' }),
      'Multi-hop is a feature when you want it: a document that flows through an organisation re-encrypts once per handoff at constant cost. Single-hop is a containment property. The BBS98 problem is not that it hops, it is that it hops WITHOUT ASKING — transitivity means the proxy composes new delegations on its own.'
    )
  );

  async function runChain(): Promise<void> {
    const text = lab.message;
    const rows: HTMLElement[] = [];
    let ct: AnyCiphertext =
      lab.scheme === 'bbs98'
        ? await bbs98.encrypt(lab.bbs('Alice'), text)
        : await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), text);
    rows.push(chainRow('encrypted to Alice', 'ok', describeLevel(ct)));

    let stoppedAt: { at: string; code: string; detail: string } | null = null;

    for (let i = 0; i < CHAIN.length - 1; i++) {
      const from = CHAIN[i]!;
      const to = CHAIN[i + 1]!;
      const rk =
        lab.scheme === 'bbs98'
          ? bbs98.rekeygen(lab.bbs(from), lab.bbs(to))
          : afgh.rekeygen(lab.afgh(from), afgh.publicKey(lab.afgh(to)));
      const id = lab.proxy.edgeId(lab.scheme, from, to);
      if (!lab.proxy.hasKey(id)) lab.proxy.install(rk);
      const result = lab.proxy.transform(id, ct);
      if (!result.ok) {
        rows.push(chainRow(`${from} → ${to}`, 'stop', `${result.code}`));
        stoppedAt = { at: `${from} → ${to}`, code: result.code, detail: result.detail };
        break;
      }
      ct = result.value;
      rows.push(chainRow(`${from} → ${to}`, 'ok', describeLevel(ct)));
    }
    lab.proxyChanged();

    // Whoever holds it now: can they read it?
    const holder = stoppedAt ? CHAIN[rowsSuccessCount(rows) - 1]! : CHAIN[CHAIN.length - 1]!;
    let read: string | null = null;
    if (ct.scheme === 'bbs98') {
      read = await bbs98.decrypt(lab.bbs(holder), ct);
    } else {
      const r = await afgh.decrypt(lab.afgh(holder), ct as AfghCiphertext);
      read = r.ok ? r.value : null;
    }

    replace(
      out,
      list('edges', rows),
      stoppedAt
        ? verdict(
            'pass',
            `The chain stopped at ${stoppedAt.at}`,
            `${stoppedAt.detail} Alice delegated to Bob and to nobody else, and that is exactly as far as her ciphertext travelled. ${holder} can still read it: "${read ?? '(no)'}"`,
            stoppedAt.code
          )
        : verdict(
            'caution',
            'The chain never stopped',
            `Three transforms, no limit reached, ciphertext the same size throughout. ${holder} — two people past anyone Alice ever agreed to — reads: "${read ?? '(no)'}". BBS98 has one ciphertext space and one decryption algorithm, so a re-encrypted ciphertext is indistinguishable from a fresh one and re-encrypts again.`
          )
    );
  }

  async function compose(): Promise<void> {
    if (lab.scheme !== 'bbs98') {
      const alice = lab.afgh('Alice');
      const bob = lab.afgh('Bob');
      const carol = lab.afgh('Carol');
      const ab = afgh.rekeygen(alice, afgh.publicKey(bob));
      const bc = afgh.rekeygen(bob, afgh.publicKey(carol));
      const ac = afgh.rekeygen(alice, afgh.publicKey(carol));
      // The only compositions available on points: addition and scaling.
      const guess = ab.value.add(bc.value);
      replace(
        out,
        verdict(
          'pass',
          'The proxy cannot mint a key it was not given',
          `A genuine rk(Alice→Carol) is g2^(a1·c2). The proxy holds g2^(a1·b2) and g2^(b1·c2); adding them gives g2^(a1·b2 + b1·c2), which is not it — checked here, and it is not: ${guess.equals(ac.value) ? 'MATCH (unexpected, please report)' : 'no match'}. Producing g2^(a1·c2) from g2^a1 and g2^c2 is the computational Diffie-Hellman problem in G2. AFGH list non-transitivity as a property of this scheme, and it follows from the same fact as everything else: the secrets are exponents, not numbers on the wire.`
        )
      );
      return;
    }
    const alice = lab.bbs('Alice');
    const bob = lab.bbs('Bob');
    const carol = lab.bbs('Carol');
    const ab = bbs98.rekeygen(alice, bob);
    const bc = bbs98.rekeygen(bob, carol);
    const composed = bbs98.composeReKeys(ab, bc);
    if (!composed.ok) {
      replace(out, verdict('fail', 'Composition refused', composed.detail, composed.code));
      return;
    }
    const genuine = bbs98.rekeygen(alice, carol);
    const same = composed.value.value === genuine.value;
    const ct = await bbs98.encrypt(alice, lab.message);
    const hopped = bbs98.reencrypt(ct, composed.value);
    const read = hopped.ok ? await bbs98.decrypt(lab.bbs('Carol'), hopped.value) : null;
    replace(
      out,
      el('div', { class: 'grid-2' }, [
        el('div', {}, [
          el('span', { class: 'field-name', text: 'rk(A→B) · rk(B→C), computed by the proxy alone' }),
          el('div', { class: `bytes ${same ? 'bytes-breach' : ''}`, text: scalarToHex(composed.value.value) }),
        ]),
        el('div', {}, [
          el('span', { class: 'field-name', text: 'a genuine rk(A→C), which Alice never issued' }),
          el('div', { class: `bytes ${same ? 'bytes-breach' : ''}`, text: scalarToHex(genuine.value) }),
        ]),
      ]),
      verdict(
        same ? 'alarm' : 'pass',
        same ? 'Identical. The proxy just minted a delegation nobody authorised' : 'Not equal',
        same
          ? `(b/a)·(c/b) = c/a. Alice agreed to Bob. Carol now reads: "${read ?? '(failed)'}". No key was stolen and no assumption was broken — multiplying two numbers is not an attack, it is arithmetic. Transitivity is a property of the scheme.`
          : 'Unexpected for BBS98 — please report.'
      )
    );
  }

  async function wrongLevel(): Promise<void> {
    if (lab.scheme === 'bbs98') {
      replace(
        out,
        verdict(
          'caution',
          'BBS98 has no levels to get wrong',
          'There is exactly one ciphertext type and one decryption algorithm, which is the same fact as "it is multi-hop" seen from the other side. WRONG_LEVEL is an AFGH failure code; switch the scheme above to reach it.'
        )
      );
      return;
    }
    const alice = lab.afgh('Alice');
    const l2 = await afgh.encryptLevel2(afgh.publicKey(alice), lab.message);
    const l1 = await afgh.encryptLevel1(afgh.publicKey(alice), lab.message, 1);
    const a = await afgh.decrypt(alice, l2, 1);
    const b = await afgh.decrypt(alice, l1, 2);
    replace(
      out,
      a.ok
        ? verdict('fail', 'A level-2 ciphertext opened by the level-1 routine', 'Unexpected — please report.')
        : verdict('fail', 'Level-1 decryptor, level-2 ciphertext', a.detail, a.code),
      b.ok
        ? verdict('fail', 'A level-1 ciphertext opened by the level-2 routine', 'Unexpected — please report.')
        : verdict('fail', 'Level-2 decryptor, level-1 ciphertext', b.detail, b.code),
      el('p', {
        class: 'step-note',
        text: 'These are type errors, not cryptographic failures. The two alphas are not even in the same group — one is 48 bytes in G1, the other 576 bytes in GT — so the mistake is caught before any arithmetic happens.',
      })
    );
  }
}

function describeLevel(ct: AnyCiphertext): string {
  if (ct.scheme === 'bbs98') return `hops so far: ${ct.hops}, still the same ciphertext type`;
  return ct.level === 2 ? 'level 2 — alpha in G1, re-encryptable' : 'level 1 — alpha in GT, terminal';
}

function chainRow(label: string, state: 'ok' | 'stop', detail: string): HTMLElement {
  return el('div', { class: `edge ${state === 'stop' ? 'edge-revoked' : ''}`.trim() }, [
    el('span', { class: 'edge-arrow', text: state === 'ok' ? '→' : 'X' }),
    el('span', { text: label }),
    el('span', { class: 'edge-meta', text: detail }),
  ]);
}

function rowsSuccessCount(rows: HTMLElement[]): number {
  return rows.filter((r) => !r.className.includes('edge-revoked')).length;
}
