/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE POINT — this is the terminal state of the
 * ratchet, not an unrun check. The gate's first full drive found four control
 * boundaries and two text colours below threshold, and every one was fixed in
 * `src/style.css` and `index.html` rather than listed here:
 *
 *   - the shared bar's `.cl-btn` drew its only boundary from a `color-mix()`
 *     of the PAGE accent and measured 2.38:1. Mixing `--cl-ink` instead makes
 *     the ratio accent-independent, which is the fleet-correct fix.
 *   - the unselected `.seg-btn` carried no border of its own and a fill
 *     identical to the card behind it: 1.00:1, i.e. no delineation at all.
 *     The border moved from the wrapper onto each button.
 *   - `--border-strong` was two steps too dark for a control boundary on
 *     `--surface-2` (2.73:1) and was lifted until every button, tab, textarea
 *     and scroll region cleared 3:1.
 *   - the cancelled exponent tokens faded to `opacity: .28`, which is muting
 *     by opacity — banned, invisible to the contrast walk, and 1.8:1. They now
 *     keep full-strength ink and carry the state in the strike-through.
 *
 * A run with `NT_BASELINE_CAPTURE=1` set prints every finding through this
 * same path and asserts nothing, which is how this file is regenerated; the
 * capture run after those fixes printed zero findings.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
