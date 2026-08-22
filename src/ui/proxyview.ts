import { el, list, p, replace, scrollRegion, verdict } from './dom';
import type { Lab } from './lab';

/**
 * The persistent proxy view.
 *
 * It sits below the tabs and never unmounts, because the claim it exists to
 * support — the proxy never learns the plaintext — is a claim about
 * EVERYTHING that happened, not about the current tab. Anything any panel
 * hands the proxy is journalled here, in the order it arrived, as the bytes the
 * proxy actually saw.
 *
 * The line that matters is the last one. "Plaintext bytes seen" is not a
 * constant: it is the result of searching every recorded byte array for the
 * message currently in the Relay tab's textarea. If the demo were lying, that
 * search would find it and the panel would say so in those words.
 */

export function renderProxyView(lab: Lab, host: HTMLElement): HTMLElement {
  const section = el('section', { class: 'proxyview', 'aria-labelledby': 'proxyview-title' });

  const head = el('div', { class: 'proxyview-head' }, [
    el('h2', { id: 'proxyview-title', class: 'proxyview-title', text: 'The proxy’s view' }),
    el('p', {
      class: 'hint',
      text: 'Everything the relay has been handed, this session. Persistent across tabs.',
    }),
  ]);
  section.appendChild(head);

  const summary = el('div', { role: 'status', 'aria-live': 'polite', 'aria-label': 'Proxy exposure summary' });
  section.appendChild(summary);

  const journal = scrollRegion('journal', 'Proxy journal, scrollable');
  section.appendChild(journal);

  function render(): void {
    const entries = lab.proxy.journal;
    const needle = new TextEncoder().encode(lab.message);
    const hit = lab.proxy.findPlaintextExposure(needle);
    const bytes = lab.proxy.bytesHandled();

    replace(
      summary,
      el('p', { class: 'exposure' }, [
        el('span', { text: `${entries.length} journal entr${entries.length === 1 ? 'y' : 'ies'} · ` }),
        el('span', { text: `${bytes} bytes handled · ` }),
        el('span', {
          class: `pill ${hit ? 'pill-bad' : 'pill-ok'}`,
          text: hit ? 'PLAINTEXT FOUND' : 'plaintext bytes found: 0',
        }),
      ]),
      hit
        ? verdict(
            'alarm',
            'The proxy is holding your message',
            `Found at journal entry ${hit.seq}, field "${hit.field}", offset ${hit.offset}. If you are seeing this, the demo is not doing what it says.`
          )
        : el('p', {
            class: 'hint',
            text:
              entries.length === 0
                ? 'Nothing yet. Run a step on any tab and it will appear here.'
                : 'That number is a search over every byte array above for the exact message in the Relay tab, not a fixed label.',
          })
    );

    replace(
      journal,
      entries.length === 0
        ? p('The relay has handled nothing so far.', 'hint')
        : list(
            'journal-list',
            entries.map((e) =>
              el('div', { class: 'journal-entry' }, [
                el('div', { class: 'journal-head' }, [
                  el('span', { class: 'journal-seq', text: `#${e.seq}` }),
                  el('span', { class: `journal-kind ${kindClass(e.kind)}`, text: kindLabel(e.kind) }),
                  el('span', { text: e.summary }),
                  e.refusalCode ? el('span', { class: 'code-tag code-fail', text: e.refusalCode }) : null,
                ]),
                e.fields.length === 0
                  ? null
                  : el(
                      'ul',
                      { class: 'journal-fields', role: 'list' },
                      e.fields.map((f) =>
                        el('li', { role: 'listitem' }, [
                          el('span', { class: 'fname', text: `${f.name}: ` }),
                          el('span', { text: f.hex.length > 96 ? `${f.hex.slice(0, 96)}…` : f.hex }),
                        ])
                      )
                    ),
              ])
            )
          )
    );
  }

  lab.onProxyChange(render);
  render();
  host.appendChild(section);
  return section;
}

function kindLabel(kind: string): string {
  switch (kind) {
    case 'rekey-installed':
      return 'KEY IN';
    case 'rekey-revoked':
      return 'KEY OUT';
    case 'ciphertext-in':
      return 'CT IN';
    case 'ciphertext-out':
      return 'CT OUT';
    default:
      return 'REFUSED';
  }
}

function kindClass(kind: string): string {
  switch (kind) {
    case 'rekey-installed':
    case 'rekey-revoked':
      return 'kind-key';
    case 'ciphertext-in':
      return 'kind-in';
    case 'ciphertext-out':
      return 'kind-out';
    default:
      return 'kind-refused';
  }
}
