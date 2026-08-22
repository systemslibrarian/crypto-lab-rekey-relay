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
 * ratchet, not an unrun check. The gate's first full drive found six control
 * boundaries under 3:1 and every one was fixed in `src/style.css` rather than
 * listed here: `.btn-primary` and the selected `.seg-btn` each painting their
 * border the SAME colour as their own accent fill (2.39:1 against the light
 * theme's white surface); the unselected `.seg-btn` dissolving into its card
 * entirely (fill 1.00:1, `--border` divider 1.37:1 dark / 1.52:1 light);
 * `.copy-secret` and both preset borders drawn as low-percentage `color-mix()`
 * toward the decorative `--border` (2.19–2.53:1); and the `.tab-btn:hover`
 * fill repainting with no edge at all (1.07–1.19:1). The shared top bar's
 * `.cl-btn`, baselined in older labs at ~1.49:1, already draws its edge from
 * `--cl-ink` here and clears 3:1 — which is why the two entries most of this
 * fleet carries are absent too.
 *
 * A run with `NT_BASELINE_CAPTURE=1` set prints every finding through this
 * same path and asserts nothing, which is how this file is regenerated; the
 * capture run after those fixes printed zero findings.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
