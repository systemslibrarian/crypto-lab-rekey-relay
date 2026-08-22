import { el } from './dom';
import type { Scheme } from '../crypto/types';

/**
 * The exponent ledger — the one mechanism this lab exists to SHOW.
 *
 * Proxy re-encryption is a single line of exponent bookkeeping, and every
 * property on this page is a consequence of it. Under BBS98 the key-carrying
 * half of the ciphertext holds `a*k`; multiplying by `rk = b/a` puts `a` next
 * to `a^-1`, they annihilate, and `b` is left where `a` was. That is the entire
 * idea. Under AFGH the same cancellation happens one group up — the pairing
 * fuses `k` with `a1*b2`, and the delegatee cancels the `b2` he contributed.
 *
 * The tokens below are not a diagram of the maths; they ARE the maths, laid out
 * so the cancellation is visible rather than asserted. The strike-through
 * animation runs ONCE, on the transform the learner triggers, and the
 * reduced-motion block in `style.css` restores its end state rather than
 * freezing it mid-flight.
 *
 * Nothing here is decorative and nothing loops.
 */

export type TokKind = 'a' | 'b' | 'k' | 'op' | 'plain';

export interface Tok {
  readonly text: string;
  readonly kind: TokKind;
  /** Marked for annihilation: this is the exponent that cancels. */
  readonly cancel?: boolean;
  /** Newly arrived in this stage. */
  readonly arrive?: boolean;
}

export type Stage = 'encrypted' | 'transformed' | 'decrypted';

function tok(t: Tok): HTMLSpanElement {
  const cls = ['tok', `tok-${t.kind}`];
  if (t.cancel) cls.push('tok-cancel');
  if (t.arrive) cls.push('tok-arrive');
  return el('span', { class: cls.join(' '), text: t.text });
}

function op(text: string): Tok {
  return { text, kind: 'op' };
}

function row(label: string, tokens: Tok[], note?: string): DocumentFragment {
  const frag = document.createDocumentFragment();
  frag.appendChild(el('div', { class: 'ledger-label', text: label }));
  const expr = el('div', { class: 'ledger-expr' }, tokens.map(tok));
  if (note) expr.appendChild(el('span', { class: 'hint', text: note }));
  frag.appendChild(expr);
  return frag;
}

/**
 * Build the ledger for a scheme at a stage.
 *
 * The first row is the message-carrying half and the second is the
 * key-carrying half, in both schemes, so the "one half moves, the other does
 * not" reading survives the scheme switch.
 */
export function buildLedger(scheme: Scheme, stage: Stage): HTMLDivElement {
  const box = el('div', { class: 'ledger' });
  const add = (f: DocumentFragment): void => {
    box.appendChild(f);
  };

  if (scheme === 'bbs98') {
    add(
      row('c1 — message', [
        { text: 'M', kind: 'plain' },
        op('·'),
        { text: 'g', kind: 'plain' },
        op('^'),
        { text: 'k', kind: 'k' },
      ], 'never touched by the proxy')
    );
    if (stage === 'encrypted') {
      add(
        row('c2 — key', [
          { text: 'g', kind: 'plain' },
          op('^'),
          { text: 'a', kind: 'a' },
          op('·'),
          { text: 'k', kind: 'k' },
        ], 'addressed to Alice')
      );
    } else if (stage === 'transformed') {
      add(
        row('rk applied', [
          { text: 'g', kind: 'plain' },
          op('^'),
          { text: 'a', kind: 'a', cancel: true },
          op('·'),
          { text: 'k', kind: 'k' },
          op('·'),
          { text: 'b', kind: 'b', arrive: true },
          op('·'),
          { text: 'a', kind: 'a', cancel: true },
          op('⁻¹'),
        ], 'rk = b · a⁻¹')
      );
      add(
        row('c2 — key', [
          { text: 'g', kind: 'plain' },
          op('^'),
          { text: 'b', kind: 'b', arrive: true },
          op('·'),
          { text: 'k', kind: 'k' },
        ], 'now addressed to Bob')
      );
    } else {
      add(
        row('c2 — key', [
          { text: 'g', kind: 'plain' },
          op('^'),
          { text: 'b', kind: 'b' },
          op('·'),
          { text: 'k', kind: 'k' },
        ])
      );
      add(
        row('Bob applies b⁻¹', [
          { text: 'g', kind: 'plain' },
          op('^'),
          { text: 'b', kind: 'b', cancel: true },
          op('·'),
          { text: 'k', kind: 'k' },
          op('·'),
          { text: 'b', kind: 'b', cancel: true },
          op('⁻¹'),
        ], '= g^k, the blinding factor in c1')
      );
    }
    return box;
  }

  // AFGH
  add(
    row('beta — message', [
      { text: 'M', kind: 'plain' },
      op('·'),
      { text: 'Z', kind: 'plain' },
      op('^'),
      { text: 'a1', kind: 'a' },
      op('·'),
      { text: 'k', kind: 'k' },
    ], 'never touched by the proxy')
  );
  if (stage === 'encrypted') {
    add(
      row('alpha — key', [
        { text: 'g1', kind: 'plain' },
        op('^'),
        { text: 'k', kind: 'k' },
      ], 'in G1 — level 2, re-encryptable')
    );
  } else if (stage === 'transformed') {
    add(
      row('pairing', [
        { text: 'e(', kind: 'op' },
        { text: 'g1', kind: 'plain' },
        op('^'),
        { text: 'k', kind: 'k' },
        { text: ',', kind: 'op' },
        { text: 'g2', kind: 'plain' },
        op('^'),
        { text: 'a1', kind: 'a', arrive: true },
        op('·'),
        { text: 'b2', kind: 'b', arrive: true },
        { text: ')', kind: 'op' },
      ], 'rk = g2^(a1 · b2)')
    );
    add(
      row('alpha — key', [
        { text: 'Z', kind: 'plain' },
        op('^'),
        { text: 'a1', kind: 'a', arrive: true },
        op('·'),
        { text: 'b2', kind: 'b', arrive: true },
        op('·'),
        { text: 'k', kind: 'k' },
      ], 'in GT — level 1, terminal')
    );
  } else {
    add(
      row('alpha — key', [
        { text: 'Z', kind: 'plain' },
        op('^'),
        { text: 'a1', kind: 'a' },
        op('·'),
        { text: 'b2', kind: 'b' },
        op('·'),
        { text: 'k', kind: 'k' },
      ])
    );
    add(
      row('Bob applies b2⁻¹', [
        { text: 'Z', kind: 'plain' },
        op('^'),
        { text: 'a1', kind: 'a' },
        op('·'),
        { text: 'b2', kind: 'b', cancel: true },
        op('·'),
        { text: 'k', kind: 'k' },
        op('·'),
        { text: 'b2', kind: 'b', cancel: true },
        op('⁻¹'),
      ], '= Z^(a1·k), the blinding factor in beta')
    );
  }
  return box;
}

/** The one-sentence reading of the stage, for anyone who cannot see the strike-through. */
export function ledgerCaption(scheme: Scheme, stage: Stage): string {
  if (scheme === 'bbs98') {
    if (stage === 'encrypted') return 'The key half carries Alice’s secret a next to the message randomness k.';
    if (stage === 'transformed')
      return 'Multiplying the key half by rk = b·a⁻¹ puts a beside a⁻¹. They cancel, and b lands where a was. The message half is untouched.';
    return 'Bob’s own b⁻¹ cancels the b, leaving g^k — exactly the factor blinding M in the message half.';
  }
  if (stage === 'encrypted')
    return 'The key half is g1^k alone: it carries no key material at all, which is what makes it re-encryptable.';
  if (stage === 'transformed')
    return 'The pairing fuses k with a1·b2 and lands the result in GT. That is a one-way step — nothing maps back out of GT, which is why there is no second hop.';
  return 'Bob cancels the b2 he contributed, leaving Z^(a1·k) — exactly the factor blinding M in the message half.';
}
