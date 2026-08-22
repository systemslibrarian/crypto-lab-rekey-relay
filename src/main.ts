import './style.css';
import { button, callout, card, details, el, h3, kicker, p, replace } from './ui/dom';
import { renderCollusion } from './ui/collusion';
import { renderGraph } from './ui/graph';
import { Lab } from './ui/lab';
import { renderOneHop } from './ui/onehop';
import { renderProxyView } from './ui/proxyview';
import { renderRelay } from './ui/relay';
import { renderUndelegate } from './ui/undelegate';
import { renderVectors } from './ui/vectors';
import type { Scheme } from './crypto/types';

/**
 * Page assembly.
 *
 * Panels render LAZILY, on first activation of their tab, and a scheme switch
 * discards every rendered panel so the next activation rebuilds against the new
 * scheme. That is deliberate rather than convenient: the scheme switch is this
 * lab's central control, and a panel that survived it would be showing BBS98
 * results under an AFGH heading.
 *
 * The proxy view is the exception — it is mounted once, outside the tab system,
 * and it accumulates. See `proxyview.ts` for why.
 */

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('#app is missing from index.html');

const lab = new Lab();

interface TabDef {
  id: string;
  label: string;
  render: (host: HTMLElement) => void;
}

const TABS: TabDef[] = [
  { id: 'relay', label: '1 · The Relay', render: (h) => renderRelay(lab, h) },
  { id: 'collusion', label: '2 · Collusion', render: (h) => renderCollusion(lab, h) },
  { id: 'onehop', label: '3 · One Hop', render: (h) => renderOneHop(lab, h) },
  { id: 'graph', label: '4 · Delegation Graph', render: (h) => renderGraph(lab, h) },
  { id: 'undelegate', label: '5 · Un-delegate', render: (h) => renderUndelegate(lab, h) },
  { id: 'vectors', label: '6 · Vectors', render: () => undefined },
];

// ── Hero ───────────────────────────────────────────────────────────────────

const hero = el('div', { class: 'cl-hero' }, [
  el('div', { class: 'cl-hero-main' }, [
    el('h1', { class: 'cl-hero-title', text: 'Rekey Relay' }),
    el('p', {
      class: 'cl-hero-sub',
      text: 'Proxy Re-Encryption · BBS98, EUROCRYPT 1998 · AFGH, NDSS 2005',
    }),
    el('p', {
      class: 'cl-hero-desc',
      text: 'Watch a semi-trusted relay convert Alice’s ciphertext into Bob’s without ever holding the message — then make the relay and Bob collude, and divide Alice’s private key out of the re-encryption key in one step.',
    }),
  ]),
  el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
    el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
    el('p', {
      class: 'cl-hero-why-text',
      text: 'Every encrypted-storage product eventually needs to share a file with someone new, and the tempting shortcut is to hand the server a key. Proxy re-encryption is the principled alternative — and the first published scheme hands the delegator’s private key to anyone who colludes. Which construction you pick decides whether "share this file" also means "surrender your key".',
    }),
  ]),
]);
app.appendChild(hero);

// ── Plain-language on-ramp ─────────────────────────────────────────────────

const intro = card('intro');
intro.appendChild(kicker('Start here'));
intro.appendChild(h3('What is proxy re-encryption?'));
intro.appendChild(
  p(
    'Imagine a locked box in a warehouse. Only you have the key. Now you want a colleague to open it, without visiting the warehouse yourself and without giving the warehouse staff your key. Proxy re-encryption gives the staff a small tool that swaps the lock on the box for one your colleague’s key opens — and the tool cannot open the box itself.'
  )
);
intro.appendChild(
  p(
    'That tool is called a re-encryption key. This page builds real ones over a real elliptic curve, hands them to a real relay, and lets you watch every byte the relay touches. Then it shows you the catch, which is bigger than it looks: in the original 1998 scheme, the relay and your colleague can put their two values side by side and divide out your private key.'
  )
);
intro.appendChild(
  p(
    'You do not need to follow the algebra to get the point. Press the buttons; the numbers are there if you want them.'
  )
);
app.appendChild(intro);

// ── Scheme switch ──────────────────────────────────────────────────────────

const schemeButtons = new Map<Scheme, HTMLButtonElement>();

function schemeButton(scheme: Scheme, label: string): HTMLButtonElement {
  const b = button(
    label,
    () => {
      setScheme(scheme);
    },
    { class: 'seg-btn', 'aria-pressed': scheme === lab.scheme }
  );
  schemeButtons.set(scheme, b);
  return b;
}

const schemeNote = el('p', { class: 'hint' });

const switcher = card('card-tight');
switcher.appendChild(
  el('div', { class: 'row' }, [
    el('span', { id: 'scheme-label', class: 'kicker', text: 'Scheme' }),
    el('div', { class: 'seg', role: 'group', 'aria-labelledby': 'scheme-label' }, [
      schemeButton('bbs98', 'BBS98 (1998)'),
      schemeButton('afgh', 'AFGH (2005)'),
    ]),
    button('New keys for everyone', () => {
      lab.regenerate();
      lab.proxyChanged();
      renderActive();
    }),
  ])
);
switcher.appendChild(schemeNote);
app.appendChild(switcher);

// ── Tabs ───────────────────────────────────────────────────────────────────

const tablist = el('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Rekey Relay exhibits' });
const panels = el('div');
const tabButtons = new Map<string, HTMLButtonElement>();
const panelHosts = new Map<string, HTMLDivElement>();
const rendered = new Set<string>();

for (const tab of TABS) {
  const b = button(
    tab.label,
    () => {
      activate(tab.id);
    },
    {
      class: 'tab-btn',
      role: 'tab',
      id: `tab-${tab.id}`,
      'aria-selected': false,
      'aria-controls': `panel-${tab.id}`,
    }
  );
  tabButtons.set(tab.id, b);
  tablist.appendChild(b);

  const host = el('div', {
    id: `panel-${tab.id}`,
    role: 'tabpanel',
    'aria-labelledby': `tab-${tab.id}`,
    tabindex: '0',
    hidden: true,
  });
  panelHosts.set(tab.id, host);
  panels.appendChild(host);
}

app.appendChild(el('nav', { 'aria-label': 'Exhibit tabs' }, [tablist]));
const main = el('main', {}, [panels]);
app.appendChild(main);

// ── Persistent proxy view ──────────────────────────────────────────────────

renderProxyView(lab, app);

// ── Honest scoping, always visible ─────────────────────────────────────────

app.appendChild(
  callout(
    'scope',
    el('strong', { text: 'Not production cryptography. ' }),
    'This is a teaching demo. What is real: the BLS12-381 group arithmetic and pairings (@noble/curves), BBS98 exactly as published, AFGH as published but re-laid onto an asymmetric pairing (the adaptation is on the Relay tab), HKDF-SHA-256 and AES-256-GCM through WebCrypto, and every failure path you can reach on this page. What is not: any key management worth the name — keys live in memory for one session and are thrown away on reload; there is no proof of possession at key registration; and neither scheme here is CCA2-secure. Do not use this code to protect anything.'
  )
);

app.appendChild(
  details(
    'What this page does NOT prove',
    p(
      'That a round trip works is a correctness demonstration, not a security proof. Nothing here rules out an attack this page does not run.'
    ),
    p(
      'That BBS98 falls to collusion is DEMONSTRATED here about as strongly as a page can manage: the recovered scalar is compared against the real one and, independently, its public key is recomputed and compared against the one Alice published. That is a demonstration on the keys in front of you, not a proof about the scheme. That AFGH does not fall the same way is demonstrated only for the specific attacks this page runs. The actual guarantee is AFGH’s master-secret-security theorem, which reduces recovery of the delegator’s secret to the discrete logarithm problem — a reduction no browser demo can reproduce.'
    ),
    p(
      'Neither paper claims security against chosen-ciphertext attack, and AFGH state explicitly that their guarantees apply "only to ciphertexts that were honestly generated by the sender; no guarantee is implied in the case of malformed ciphertexts". The MALFORMED_RK and RK_MISMATCH refusals on this page are implementation hygiene, outside both papers’ models — worth having, not scheme properties.'
    ),
    p(
      'The AFGH scheme is written in its original papers for a symmetric pairing. BLS12-381 is Type-3, so the source-group roles are split across G1 and G2. That split is forced by the pairing’s signature rather than chosen, and the Relay tab’s "How AFGH was moved onto an asymmetric pairing" disclosure spells it out — but it is an adaptation, and the security arguments were written for the symmetric setting.'
    )
  )
);

// ── Footer ─────────────────────────────────────────────────────────────────

const footer = el('footer', { class: 'scripture-footer' }, [
  el('p', {
    text: 'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
  }),
]);
document.body.appendChild(footer);

// ── Behaviour ──────────────────────────────────────────────────────────────

let activeId = TABS[0]!.id;

function activate(id: string): void {
  activeId = id;
  for (const tab of TABS) {
    const selected = tab.id === id;
    tabButtons.get(tab.id)!.setAttribute('aria-selected', String(selected));
    const host = panelHosts.get(tab.id)!;
    if (selected) host.removeAttribute('hidden');
    else host.setAttribute('hidden', '');
  }
  renderIfNeeded(id);
}

function renderIfNeeded(id: string): void {
  if (rendered.has(id)) return;
  const host = panelHosts.get(id)!;
  const tab = TABS.find((t) => t.id === id)!;
  if (id === 'vectors') renderVectors(host);
  else tab.render(host);
  rendered.add(id);
}

function renderActive(): void {
  for (const id of rendered) replace(panelHosts.get(id)!);
  rendered.clear();
  renderIfNeeded(activeId);
}

function setScheme(scheme: Scheme): void {
  if (lab.scheme === scheme) return;
  lab.setScheme(scheme);
  for (const [s, b] of schemeButtons) b.setAttribute('aria-pressed', String(s === scheme));
  updateSchemeNote();
  renderActive();
}

function updateSchemeNote(): void {
  schemeNote.textContent =
    lab.scheme === 'bbs98'
      ? 'BBS98 — Blaze, Bleumer and Strauss, EUROCRYPT 1998. The first proxy re-encryption scheme: ElGamal-based, bidirectional, multi-hop, transitive, and broken by collusion. Every tab runs this scheme until you switch.'
      : 'AFGH — Ateniese, Fu, Green and Hohenberger, NDSS 2005, section 3.1 "A Third Attempt". Pairing-based, unidirectional, non-interactive, single-hop, and collusion-safe for the master secret only. Every tab now runs this scheme instead.';
}

updateSchemeNote();
activate(TABS[0]!.id);
