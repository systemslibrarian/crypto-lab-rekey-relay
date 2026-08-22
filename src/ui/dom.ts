/**
 * Tiny DOM helpers.
 *
 * Deliberately not a framework: every node this page paints is created here in
 * one place, which is what makes the accessibility rules auditable by reading
 * the source rather than by diffing a render tree. `text` is always assigned
 * through `textContent`, never `innerHTML`, so nothing on this page can inject
 * markup from a value the learner typed.
 */

type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string | null | undefined)[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined) continue;
    // ARIA state attributes are STRING enumerations, not HTML boolean
    // attributes. `aria-pressed=""` is not "pressed" and a missing
    // `aria-pressed` is not "not pressed" — it removes the toggle semantics
    // altogether. So aria-* is always stringified, and only real boolean
    // attributes (hidden, disabled) get the presence/absence treatment.
    if (k.startsWith('aria-')) {
      node.setAttribute(k, String(v));
      continue;
    }
    if (v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'html') throw new Error('innerHTML is not used on this page');
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function replace(node: Element, ...children: (Node | null | undefined)[]): void {
  clear(node);
  for (const c of children) if (c) node.appendChild(c);
}

export function h2(text: string): HTMLHeadingElement {
  return el('h2', { text });
}

export function h3(text: string): HTMLHeadingElement {
  return el('h3', { text });
}

export function h4(text: string): HTMLHeadingElement {
  return el('h4', { text });
}

export function p(text: string, cls?: string): HTMLParagraphElement {
  return el('p', cls ? { text, class: cls } : { text });
}

export function kicker(text: string): HTMLParagraphElement {
  return el('p', { text, class: 'kicker' });
}

export function card(cls = ''): HTMLDivElement {
  return el('div', { class: `card ${cls}`.trim() });
}

export function button(
  label: string,
  onClick: () => void | Promise<void>,
  attrs: Attrs = {}
): HTMLButtonElement {
  const b = el('button', { type: 'button', ...attrs }, [label]);
  b.addEventListener('click', () => {
    void onClick();
  });
  return b;
}

/**
 * A live output region.
 *
 * `role="status"` + `aria-live="polite"` because everything this page computes
 * lands asynchronously (WebCrypto is promise-based) and a screen-reader user
 * would otherwise never be told a verdict had appeared.
 */
export function liveRegion(label: string): HTMLDivElement {
  return el('div', { role: 'status', 'aria-live': 'polite', 'aria-label': label });
}

export type VerdictTone = 'pass' | 'caution' | 'fail' | 'alarm';

const TONE_ICON: Record<VerdictTone, string> = {
  pass: 'OK',
  caution: '!',
  fail: 'X',
  alarm: '!!',
};

/**
 * A verdict: icon + text + colour, never colour alone (WCAG 1.4.1).
 *
 * The icon is a short mono token rather than a glyph font, and it is inside the
 * accessible name of the block, so the state survives greyscale, deuteranopia
 * and a screen reader alike.
 */
export function verdict(
  tone: VerdictTone,
  headline: string,
  detail?: string | Node,
  code?: string
): HTMLDivElement {
  const body = el('div', { class: 'verdict-body' }, [el('strong', { text: headline })]);
  if (code) {
    body.insertBefore(
      el('span', {
        class: `code-tag ${tone === 'alarm' ? 'code-alarm' : tone === 'fail' ? 'code-fail' : 'code-warn'}`,
        text: code,
      }),
      body.firstChild
    );
  }
  if (detail !== undefined) {
    body.appendChild(typeof detail === 'string' ? el('p', { text: detail }) : detail);
  }
  return el('div', { class: `verdict verdict-${tone}` }, [
    el('span', { class: 'verdict-icon', text: TONE_ICON[tone] }),
    body,
  ]);
}

/** A labelled byte field, with an optional same/changed tag. */
export function byteField(
  name: string,
  hex: string,
  state?: 'same' | 'diff'
): HTMLDivElement {
  const label = el('span', { class: 'field-name' }, [name]);
  if (state) {
    label.appendChild(
      el('span', {
        class: `tag tag-${state}`,
        text: state === 'same' ? 'BYTE-IDENTICAL' : 'CHANGED',
      })
    );
  }
  return el('div', { class: 'field' }, [
    label,
    el('div', { class: `bytes ${state ? `bytes-${state}` : ''}`.trim(), text: hex }),
  ]);
}

/**
 * A progressive-disclosure block. Ships SHUT — the arrival state a reader gets
 * is the simple one, and the depth is one click away.
 */
export function details(summaryText: string, ...body: (Node | string)[]): HTMLDetailsElement {
  const d = el('details');
  d.appendChild(el('summary', { text: summaryText }));
  d.appendChild(el('div', { class: 'details-body' }, body));
  return d;
}

export function callout(kind: 'scope' | 'danger' | 'caveat', ...body: (Node | string)[]): HTMLDivElement {
  return el('div', { class: `callout callout-${kind}` }, body);
}

/** A list with explicit list semantics, which `list-style: none` would drop. */
export function list(cls: string, items: Node[]): HTMLUListElement {
  return el(
    'ul',
    { class: cls, role: 'list' },
    items.map((n) => el('li', { role: 'listitem' }, [n]))
  );
}

/**
 * A scrollable region that is reachable from the keyboard.
 *
 * `overflow: auto` alone builds a scroller no keyboard user can scroll, and
 * axe has no rule for it. `tabindex="0"` + `role="region"` + a label is the
 * documented fix, and `e2e/gate.ts` asserts it at every driven state.
 */
export function scrollRegion(cls: string, label: string): HTMLDivElement {
  return el('div', { class: cls, tabindex: '0', role: 'region', 'aria-label': label });
}

/**
 * A table inside a keyboard-reachable horizontal scroll region.
 *
 * `overflow-x: auto` on its own builds a scroller no keyboard user can reach —
 * axe flags it as `scrollable-region-focusable`, and it is a WCAG 2.1.1
 * failure whether or not axe is watching. At 380px every table on this page
 * scrolls, so this is the only correct way to ship one.
 */
export function tableWrap(label: string, table: HTMLTableElement): HTMLDivElement {
  return el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': label }, [
    table,
  ]);
}

export function shortHex(hex: string, head = 16, tail = 8): string {
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`;
}
