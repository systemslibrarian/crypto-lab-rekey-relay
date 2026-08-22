import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
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
import type { Lab } from './lab';

/**
 * The negative claim, run rather than stated.
 *
 * NEITHER scheme on this page provides cryptographic revocation of a
 * re-encryption capability that has already been issued. Deleting rk from the
 * proxy works exactly as long as the proxy chooses to honour it; and if the
 * proxy and the delegatee ever colluded, deleting it accomplishes nothing at
 * all, because the residue they hold works offline.
 *
 * That claim has to be SCOPED, because stated flatly it is refutable by the
 * AFGH paper itself. Their section 3.6 gives a temporary unidirectional scheme
 * with a genuine cryptographic revocation: a trusted server broadcasts a fresh
 * random h_i each period, every rk is pinned to that period's h_i, and
 * advancing the period invalidates every outstanding delegation at once — "A
 * single global change can invalidate all previous delegations without any user
 * needing to change their public key." It is forward-only, it needs a trusted
 * beacon, and its rekeygen is interactive, but it is real, and it is in the same
 * paper. So the claim here is about the two constructions this page implements,
 * not about proxy re-encryption as a field.
 *
 * The named alternatives, and the distinction between them, are in the
 * disclosure at the bottom of this panel and in the README's "What Can Go
 * Wrong". The distinction matters: conditional, type-based and attribute-based
 * PRE are routinely miscited as revocation, and they are not — they narrow what
 * a delegation covers, and once issued they are just as permanent.
 */

export function renderUndelegate(lab: Lab, host: HTMLElement): void {
  const out = liveRegion('Revocation result');
  const steps = el('div');

  const bRun = button('Try to un-delegate', () => void run(), { class: 'btn-danger' });
  const bRotate = button('Do it the only way that works', () => void rotate(), { disabled: true });

  const intro = card('intro');
  intro.appendChild(kicker('The negative claim'));
  intro.appendChild(h3('Alice changes her mind'));
  intro.appendChild(
    p(
      'Delegation is easy. Un-delegation is the part nobody puts on the slide. Alice granted Bob read access through the relay; now Bob has left the company. She tells the relay to delete the key. Watch what that does and does not accomplish.'
    )
  );
  intro.appendChild(
    p(
      'This runs in five steps, all against the real schemes. Nothing here is a hypothetical.'
    )
  );
  host.appendChild(intro);

  const controls = card();
  controls.appendChild(
    el('div', { class: 'row', role: 'group', 'aria-label': 'Revocation controls' }, [bRun, bRotate])
  );
  controls.appendChild(steps);
  controls.appendChild(out);
  host.appendChild(controls);

  host.appendChild(
    callout(
      'scope',
      el('strong', { text: 'Scope of that claim. ' }),
      'It is about BBS98 and the AFGH construction on this page, not about proxy re-encryption in general. PRE schemes designed with revocation exist, including one by the AFGH authors themselves — the disclosure below names them, and separates the ones that actually revoke from the ones that only narrow a delegation.'
    )
  );

  host.appendChild(
    details(
      'Schemes that DO address revocation, and what each one really does',
      el('h4', { text: 'Cryptographic revocation, forward-only' }),
      p(
        'Ateniese, Fu, Green and Hohenberger, "Improved Proxy Re-encryption Schemes with Applications to Secure Distributed Storage", section 3.6 — the temporary unidirectional scheme in the same paper as the construction on this page. A trusted server broadcasts a fresh random h_i for each time period; every re-encryption key is pinned to its period, so advancing the period invalidates all outstanding delegations at once. The costs are a trusted beacon, an interactive rekeygen, and the fact that a stale key still re-encrypts anything encrypted DURING its period.'
      ),
      p(
        'Liu, Wang and Wu, "Time-based proxy re-encryption scheme for secure data sharing in a cloud environment", Information Sciences 258:355–370, 2014 — attaches a time tree to a CP-ABE/PRE hybrid so attributes carry eligible periods.'
      ),
      el('h4', { text: 'Scope narrowing, often miscited as revocation' }),
      p(
        'Weng, Deng, Ding, Chu and Lai, "Conditional proxy re-encryption secure against chosen-ciphertext attack", ASIACCS 2009 — binds rk to a keyword, so the proxy transforms only ciphertexts carrying it. Tang, "Type-Based Proxy Re-encryption and Its Construction", INDOCRYPT 2008 — the same idea over message types. Liang, Cao, Lin and Shao, "Attribute based proxy re-encryption with delegating capabilities", ASIACCS 2009 — gates re-encryption on an attribute policy.'
      ),
      p(
        'None of these three revokes anything. Once the condition is fixed and the key is out, the proxy re-encrypts every matching ciphertext forever. They reduce the blast radius of a delegation; they are the wrong citation for withdrawing one.'
      ),
      el('h4', { text: 'The state of the art, and its own admission' }),
      p(
        'Schemes that update the re-encryption key on revocation still have to update the stored CIPHERTEXTS too, or the proxy keeps transforming everything from before the update with the old key. That is "rotate and re-encrypt" relocated to the server — and it only works if the server actually runs the pass and discards what came before, which is a trust assumption rather than a cryptographic one.'
      ),
      p(
        'The clean way to state the limit: a re-encryption key is a capability over a SET of ciphertexts, not over a session. Revocation can shrink which future ciphertexts join that set. It cannot claw back one already in it.'
      )
    )
  );

  host.appendChild(
    callout(
      'caveat',
      el('strong', { text: 'And nothing in either paper is non-transferable. ' }),
      'AFGH’s own comparison table scores non-transferability "No" for every scheme in it, including theirs, with the note that no scheme achieves it. Once the colluders hold the residue, it is a small value they can hand to anyone — which is why step 4 below still succeeds after the key is deleted.'
    )
  );

  async function run(): Promise<void> {
    const rows: HTMLElement[] = [];
    const id = lab.proxy.edgeId(lab.scheme, 'Alice', 'Bob');

    // 1. delegate
    if (lab.scheme === 'bbs98') {
      lab.proxy.install(bbs98.rekeygen(lab.bbs('Alice'), lab.bbs('Bob')));
    } else {
      lab.proxy.install(afgh.rekeygen(lab.afgh('Alice'), afgh.publicKey(lab.afgh('Bob'))));
    }
    rows.push(step(1, 'Alice delegates to Bob', 'ok', 'the proxy stores the re-encryption key'));

    // 2. it works
    const first =
      lab.scheme === 'bbs98'
        ? await bbs98.encrypt(lab.bbs('Alice'), lab.message)
        : await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), lab.message);
    const hop = lab.proxy.transform(id, first);
    rows.push(
      step(2, 'A message relays to Bob', hop.ok ? 'ok' : 'stop', hop.ok ? 'transformed and delivered' : hop.code)
    );

    // 3. the colluders take their residue BEFORE the revocation
    let residue: { kind: 'sk'; value: bigint } | { kind: 'weak'; value: ReturnType<typeof afgh.collude>['weakKey'] };
    if (lab.scheme === 'bbs98') {
      const rk = bbs98.rekeygen(lab.bbs('Alice'), lab.bbs('Bob'));
      residue = { kind: 'sk', value: bbs98.collude(rk, lab.bbs('Bob').sk, lab.bbs('Alice').pk, lab.bbs('Alice').sk).recovered };
      rows.push(step(3, 'Bob and the proxy collude, once', 'warn', 'they keep Alice’s private key a'));
    } else {
      const rk = afgh.rekeygen(lab.afgh('Alice'), afgh.publicKey(lab.afgh('Bob')));
      residue = { kind: 'weak', value: afgh.collude(rk, lab.afgh('Bob').a2, lab.afgh('Alice')).weakKey };
      rows.push(step(3, 'Bob and the proxy collude, once', 'warn', 'they keep the weak key g2^a1'));
    }

    // 4. Alice revokes
    const revoked = lab.proxy.revoke(id);
    lab.proxyChanged();
    const afterRevoke =
      lab.scheme === 'bbs98'
        ? lab.proxy.transform(id, await bbs98.encrypt(lab.bbs('Alice'), lab.message))
        : lab.proxy.transform(id, await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), lab.message));
    lab.proxyChanged();
    rows.push(
      step(
        4,
        'Alice revokes: the proxy deletes the key',
        revoked && !afterRevoke.ok ? 'ok' : 'stop',
        !afterRevoke.ok ? `the proxy now refuses: ${afterRevoke.code}` : 'still transforming — unexpected'
      )
    );

    // 5. but the residue still reads new mail
    const secret = 'Written the day after Alice revoked. Nobody should be able to read this.';
    let read: string | null = null;
    if (residue.kind === 'sk') {
      const later = await bbs98.encrypt(lab.bbs('Alice'), secret);
      read = await bbs98.decrypt(bbs98.keypairFromScalar('impostor', residue.value), later);
    } else {
      const later = await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), secret);
      read = await afgh.decryptWithWeakKey(residue.value, later);
    }
    rows.push(
      step(
        5,
        'A message written AFTER the revocation',
        read === secret ? 'stop' : 'ok',
        read === secret ? 'the colluders read it anyway' : 'unreadable'
      )
    );

    replace(steps, list('edges', rows));
    replace(
      out,
      el('div', {}, [
        el('span', { class: 'field-name', text: 'what the colluders read, after revocation' }),
        el('div', { class: `bytes ${read === secret ? 'bytes-breach' : 'bytes-same'}`, text: read ?? '(unreadable)' }),
      ]),
      read === secret
        ? verdict(
            'alarm',
            'The revocation revoked nothing',
            lab.scheme === 'bbs98'
              ? 'Deleting rk stopped the proxy from doing the transform. It did not take back Alice’s private key, which is what the colluders actually walked away with. Every message she sends from now on is theirs, and there is no cryptographic operation available to her that changes that — only rotating to a new key pair and re-encrypting everything, which is the work proxy re-encryption was adopted to avoid.'
              : 'Deleting rk stopped the proxy. It did not take back g2^a1, and g2^a1 opens level-2 ciphertexts without any proxy at all — including ones written after the revocation. AFGH is careful about this: the residue is bounded to the capability already delegated, but "bounded" and "withdrawn" are different words.'
          )
        : verdict('pass', 'Revocation held', 'Unexpected on this page — please report.')
    );
    bRotate.disabled = false;
  }

  async function rotate(): Promise<void> {
    const secret = 'Written after Alice rotated her key pair and re-encrypted everything.';
    if (lab.scheme === 'bbs98') {
      const old = lab.bbs('Alice');
      const rk = bbs98.rekeygen(old, lab.bbs('Bob'));
      const stolen = bbs98.collude(rk, lab.bbs('Bob').sk, old.pk, old.sk).recovered;
      const fresh = bbs98.keygen('Alice-v2');
      const ct = await bbs98.encrypt(fresh, secret);
      const attempt = await bbs98.decrypt(bbs98.keypairFromScalar('impostor', stolen), ct);
      replace(
        out,
        verdict(
          attempt === null ? 'pass' : 'alarm',
          attempt === null ? 'The stolen key is now worthless' : 'Still readable — unexpected',
          attempt === null
            ? 'Alice generated a new key pair and re-encrypted her data under it. That is the only move that retires an already-issued capability, and it costs exactly what proxy re-encryption exists to avoid: touching every ciphertext. It also has to be done for every delegation she ever issued, not just the compromised one, because she cannot tell which rk leaked.'
            : 'Please report.'
        )
      );
      return;
    }
    const old = lab.afgh('Alice');
    const rk = afgh.rekeygen(old, afgh.publicKey(lab.afgh('Bob')));
    const weak = afgh.collude(rk, lab.afgh('Bob').a2, old).weakKey;
    const fresh = afgh.keygen('Alice-v2');
    const ct = await afgh.encryptLevel2(afgh.publicKey(fresh), secret);
    const attempt = await afgh.decryptWithWeakKey(weak, ct);
    replace(
      out,
      verdict(
        attempt === null ? 'pass' : 'alarm',
        attempt === null ? 'The weak key is now worthless' : 'Still readable — unexpected',
        attempt === null
          ? 'A fresh a1 means a fresh Z^a1, and the old g2^a1 pairs against nothing useful. Same conclusion as BBS98, same cost: every stored ciphertext has to be re-encrypted under the new key, and every delegation reissued.'
          : 'Please report.'
      )
    );
  }
}

function step(n: number, label: string, state: 'ok' | 'warn' | 'stop', detail: string): HTMLElement {
  return el('span', { class: `edge ${state === 'stop' ? 'edge-revoked' : ''}`.trim() }, [
    el('span', { class: 'edge-arrow', text: state === 'ok' ? 'OK' : state === 'warn' ? '!' : 'X' }),
    el('span', { text: `${n}. ${label}` }),
    el('span', { class: 'edge-meta', text: detail }),
  ]);
}
