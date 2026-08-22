import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import { bytesToHex, g1ToBytes, gtToBytes } from '../crypto/group';
import {
  button,
  card,
  details,
  el,
  h3,
  h4,
  kicker,
  liveRegion,
  list,
  p,
  replace,
  tableWrap,
  verdict,
} from './dom';
import { CAST, type Actor, type Lab } from './lab';

/**
 * Act 5 — the delegation graph.
 *
 * The demo's whole first act is about what the proxy does NOT learn. This act
 * is about what it cannot help learning, and for a lot of deployments that is
 * the part that matters. A proxy that relays encrypted messages for a hospital
 * learns which consultant reads which patient's file. One relaying for a
 * newsroom learns which journalist reads which source's drop. It never sees a
 * byte of content and it has the entire org chart.
 *
 * Two things sharpen it beyond "the proxy sees metadata":
 *
 *  - Under BBS98 the graph the proxy can ACT on is bigger than the graph it was
 *    given, because rk(A→B)·rk(B→C) = rk(A→C). The transitive closure below is
 *    computed and shown next to the issued edges, and the difference is
 *    delegations nobody authorised.
 *
 *  - The link between an input ciphertext and its re-encrypted output is public
 *    to ANY observer, in both schemes, with no proxy cooperation at all. The
 *    message-carrying half is byte-identical across the hop — the same property
 *    the Relay tab uses to prove the proxy did not touch the message is what
 *    makes the two ciphertexts trivially linkable.
 */

export function renderGraph(lab: Lab, host: HTMLElement): void {
  const graphBox = el('div');
  const out = liveRegion('Graph result');

  const intro = card('intro');
  intro.appendChild(kicker('Act 5 — What the relay knows anyway'));
  intro.appendChild(h3('No plaintext, and the whole org chart'));
  intro.appendChild(
    p(
      'Everything so far has been about the content the proxy never sees. Now look at what it holds instead. Every re-encryption key it stores is a statement — this person has granted that person read access — and it needs that statement to do its job at all. There is no version of this scheme where the relay is ignorant of the graph.'
    )
  );
  intro.appendChild(
    p(
      'For plenty of systems the graph IS the sensitive part. Which consultant reads which patient record. Which journalist opens which source’s drop. Which two firms are talking before the merger is announced. Encryption protects the message; it does not protect the fact of the relationship.'
    )
  );
  host.appendChild(intro);

  const builder = card();
  builder.appendChild(h4('Add delegations and watch the graph grow'));
  const buttons = el('div', { class: 'row', role: 'group', 'aria-label': 'Delegation builder' });
  const PAIRS: [Actor, Actor][] = [
    ['Alice', 'Bob'],
    ['Bob', 'Carol'],
    ['Carol', 'Dave'],
    ['Alice', 'Dave'],
  ];
  for (const [from, to] of PAIRS) {
    buttons.appendChild(button(`${from} → ${to}`, () => addEdge(from, to)));
  }
  buttons.appendChild(
    button('Clear the proxy', () => {
      lab.proxy.reset();
      lab.proxyChanged();
      render();
      replace(out);
    })
  );
  builder.appendChild(buttons);
  builder.appendChild(graphBox);
  host.appendChild(builder);

  const evidence = card();
  evidence.appendChild(kicker('The other leak'));
  evidence.appendChild(h3('Anyone watching can link the before and the after'));
  evidence.appendChild(
    p(
      'This one does not even need the proxy’s cooperation. Press the button: it encrypts, transforms, and prints the message-carrying half of both ciphertexts side by side. They are the same bytes. That is the property the Relay tab uses to prove the proxy never touched the message — and it is also what makes an input and its re-encrypted output trivially linkable by a passive observer.'
    )
  );
  evidence.appendChild(button('Show the link', () => void showLink(), { class: 'btn-primary' }));
  evidence.appendChild(out);
  host.appendChild(evidence);

  host.appendChild(
    details(
      'What a deployment can and cannot do about this',
      p(
        'It can shrink the graph. Conditional and type-based proxy re-encryption bind a re-encryption key to a keyword or a message type, so one key covers a slice of Alice’s inbox instead of all of it (Weng, Deng, Ding, Chu and Lai, ASIACCS 2009; Tang, INDOCRYPT 2008). That reduces what a single edge implies. It does not remove the edge.'
      ),
      p(
        'It can hide who is asking, with an anonymity network or a mixnet in front of the proxy, at the cost of latency and a much larger system. It can shard delegations across proxies that do not collude, which is a trust assumption rather than a cryptographic guarantee.'
      ),
      p(
        'What it cannot do is run a proxy re-encryption service without the proxy learning the delegation graph. That is not an implementation gap; the re-encryption key IS the relationship, and the proxy has to hold it to transform anything.'
      )
    )
  );

  function addEdge(from: Actor, to: Actor): void {
    const rk =
      lab.scheme === 'bbs98'
        ? bbs98.rekeygen(lab.bbs(from), lab.bbs(to))
        : afgh.rekeygen(lab.afgh(from), afgh.publicKey(lab.afgh(to)));
    lab.proxy.install(rk);
    lab.proxyChanged();
    render();
  }

  function render(): void {
    const edges = lab.proxy.delegations.filter((e) => e.scheme === lab.scheme);
    const live = edges.filter((e) => !e.revoked);
    const nodes = CAST.filter((n) => edges.some((e) => e.from === n || e.to === n));

    // An empty `role="list"` fails axe's `aria-required-children`, so the
    // no-edges case renders a sentence instead of an empty list.
    const nodeList =
      nodes.length === 0
        ? p('Nobody is on the graph yet — install a delegation above.', 'hint')
        : list(
            'nodes',
            nodes.map((n) =>
              el('span', {
                class: `node ${live.some((e) => e.from === n) ? 'node-src' : live.some((e) => e.to === n) ? 'node-dst' : ''}`.trim(),
                text: n,
              })
            )
          );

    const edgeList =
      edges.length === 0
        ? p('No delegations installed yet.', 'hint')
        : list(
            'edges',
            edges.map((e) =>
            el('span', { class: `edge ${e.revoked ? 'edge-revoked' : ''}`.trim() }, [
              el('span', { text: e.from }),
              el('span', { class: 'edge-arrow', text: '→' }),
              el('span', { text: e.to }),
              el('span', {
                class: 'edge-meta',
                text: `installed at t${e.installedAt} · ${e.uses} transform${e.uses === 1 ? '' : 's'}${e.revoked ? ' · REVOKED' : ''}`,
              }),
            ])
            )
          );

    replace(graphBox, el('h4', { text: 'Nodes' }), nodeList, el('h4', { text: 'Issued edges' }), edgeList);

    if (live.length === 0) return;

    // Every two-step path in the issued graph, with the composition ATTEMPTED
    // rather than assumed. Under BBS98 the proxy multiplies two scalars and the
    // result verifies against the two public keys; under AFGH the only moves
    // available on points do not land on the genuine key, and the check says so
    // because it ran, not because the scheme's name implies it.
    const paths = twoStepPaths(live.map((e) => [e.from, e.to] as [Actor, Actor]));
    const rows: HTMLElement[] = live.map((e) =>
      el('tr', {}, [
        el('td', { text: e.from }),
        el('td', { text: e.to }),
        el('td', { text: 'issued by the delegator' }),
      ])
    );
    let composedCount = 0;
    const composedLabels: string[] = [];
    for (const [from, via, to] of paths) {
      const outcome = attemptComposition(lab, from, via, to);
      if (outcome.works) {
        composedCount++;
        composedLabels.push(`${from}→${to}`);
      }
      rows.push(
        el('tr', {}, [
          el('td', { text: from }),
          el('td', { text: to }),
          el('td', { text: `${outcome.works ? 'COMPOSED by the proxy' : 'not composable'} — via ${via}: ${outcome.detail}` }),
        ])
      );
    }

    graphBox.appendChild(el('h4', { text: 'What the proxy can actually do' }));
    graphBox.appendChild(
      tableWrap(
        'Delegations the proxy can perform, scrollable',
        el('table', {}, [
          el('caption', {
            text: 'Every issued edge, plus every two-step path with the composition actually attempted.',
          }),
          el('thead', {}, [
            el('tr', {}, [
              el('th', { text: 'from' }),
              el('th', { text: 'to' }),
              el('th', { text: 'origin' }),
            ]),
          ]),
          el('tbody', {}, rows),
        ])
      )
    );

    if (paths.length === 0) {
      graphBox.appendChild(
        el('p', {
          class: 'hint',
          text: 'No two-step path in this graph yet — install a second edge that starts where another ends.',
        })
      );
    } else if (composedCount > 0) {
      graphBox.appendChild(
        verdict(
          'alarm',
          `${composedCount} delegation${composedCount === 1 ? '' : 's'} nobody issued`,
          `(b/a)·(c/b) = c/a. The proxy multiplied the scalars it already holds and the result VERIFIES against the two public keys: ${composedLabels.join(', ')}. Alice agreed to Bob. Nobody agreed to this.`
        )
      );
    } else {
      graphBox.appendChild(
        verdict(
          'pass',
          'The graph the proxy can act on is exactly the graph it was given',
          `${paths.length} two-step path${paths.length === 1 ? '' : 's'} attempted, none composable. A re-encryption key here is a point, and building g2^(a1·c2) from g2^(a1·b2) and g2^(b1·c2) is the computational Diffie-Hellman problem in G2 — the additions and scalings a proxy can perform were tried and none of them lands on the genuine key.`
        )
      );
    }
  }

  async function showLink(): Promise<void> {
    if (lab.scheme === 'bbs98') {
      const before = await bbs98.encrypt(lab.bbs('Alice'), lab.message);
      const after = bbs98.reencrypt(before, bbs98.rekeygen(lab.bbs('Alice'), lab.bbs('Bob')));
      if (!after.ok) {
        replace(out, verdict('fail', 'Transform refused', after.detail, after.code));
        return;
      }
      const b = bytesToHex(g1ToBytes(before.c1));
      const a = bytesToHex(g1ToBytes(after.value.c1));
      replace(out, linkPanel('c1 before the hop', b, 'c1 after the hop', a));
      return;
    }
    const before = await afgh.encryptLevel2(afgh.publicKey(lab.afgh('Alice')), lab.message);
    const after = afgh.reencrypt(before, afgh.rekeygen(lab.afgh('Alice'), afgh.publicKey(lab.afgh('Bob'))));
    if (!after.ok) {
      replace(out, verdict('fail', 'Transform refused', after.detail, after.code));
      return;
    }
    const b = bytesToHex(gtToBytes(before.beta));
    const a = bytesToHex(gtToBytes(after.value.beta));
    replace(out, linkPanel('beta before the hop', b, 'beta after the hop', a));
  }

  render();
}

function linkPanel(l1: string, v1: string, l2: string, v2: string): HTMLElement {
  const same = v1 === v2;
  return el('div', {}, [
    el('div', { class: 'grid-2' }, [
      el('div', {}, [
        el('span', { class: 'field-name', text: l1 }),
        el('div', { class: `bytes ${same ? 'bytes-bounded' : ''}`, text: v1 }),
      ]),
      el('div', {}, [
        el('span', { class: 'field-name', text: l2 }),
        el('div', { class: `bytes ${same ? 'bytes-bounded' : ''}`, text: v2 }),
      ]),
    ]),
    same
      ? verdict(
          'caution',
          'Identical — and that cuts both ways',
          'This is the same byte comparison the Relay tab uses to show the proxy never touched the message. Read from the other side, it means an observer who saw the ciphertext go in and the ciphertext come out can pair them with a string comparison, and thereby learn that a delegation was exercised, when, and between which two stored objects. Both AFGH and BBS98 have this shape.'
        )
      : verdict('fail', 'Not identical', 'Unexpected — please report.'),
  ]);
}

/** Every from → via → to path in the issued graph, excluding the trivial ones. */
function twoStepPaths(edges: [Actor, Actor][]): [Actor, Actor, Actor][] {
  const out: [Actor, Actor, Actor][] = [];
  for (const [a, b] of edges) {
    for (const [c, d] of edges) {
      if (b !== c || a === d) continue;
      if (edges.some(([x, y]) => x === a && y === d)) continue; // already issued
      out.push([a, b, d]);
    }
  }
  return out;
}

/**
 * Attempt the composition the proxy would attempt, and report what happened.
 *
 * BBS98: multiply the two scalars and CHECK the result against the two public
 * keys with `verifyReKey`, which needs nothing secret. If it verifies, the
 * proxy holds a working delegation nobody issued.
 *
 * AFGH: the re-encryption key is a point, so the operations available are
 * addition and scaling by a known scalar. Both are tried against the genuine
 * rk(from → to). Neither lands on it, and the reason is that producing
 * g2^(a1·c2) from g2^(a1·b2) and g2^(b1·c2) is CDH in G2.
 */
function attemptComposition(
  lab: Lab,
  from: Actor,
  via: Actor,
  to: Actor
): { works: boolean; detail: string } {
  if (lab.scheme === 'bbs98') {
    const composed = bbs98.composeReKeys(
      bbs98.rekeygen(lab.bbs(from), lab.bbs(via)),
      bbs98.rekeygen(lab.bbs(via), lab.bbs(to))
    );
    if (!composed.ok) return { works: false, detail: composed.detail };
    const works = bbs98.verifyReKey(composed.value);
    return {
      works,
      detail: works
        ? 'the product of two scalars, and it verifies against both public keys'
        : 'the product does not verify',
    };
  }
  const ab = afgh.rekeygen(lab.afgh(from), afgh.publicKey(lab.afgh(via)));
  const bc = afgh.rekeygen(lab.afgh(via), afgh.publicKey(lab.afgh(to)));
  const genuine = afgh.rekeygen(lab.afgh(from), afgh.publicKey(lab.afgh(to)));
  const tried = [ab.value.add(bc.value), ab.value.subtract(bc.value), ab.value.double()];
  const works = tried.some((p) => p.equals(genuine.value));
  return {
    works,
    detail: works ? 'unexpected — please report' : 'adding, subtracting and doubling the two points all miss the genuine key (CDH in G2)',
  };
}
