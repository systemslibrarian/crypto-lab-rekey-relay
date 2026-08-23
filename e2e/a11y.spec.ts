import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  REFLOW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned:
 * the arrival state with nothing yet encrypted and five tabpanels hidden AND
 * UNRENDERED; the shared skip link focused; BBS98 end to end and then AFGH end
 * to end, since the scheme switch discards every rendered panel and half the
 * page's states exist only on one side; all four relay steps and all three
 * break-it controls under BOTH schemes; the retirement state and the manual
 * reset; all five failure codes — MALFORMED_RK, RK_MISMATCH,
 * ALREADY_REENCRYPTED, WRONG_LEVEL and the COLLUSION_KEY_RECOVERED alarm; the
 * AFGH collusion's bounded-residue caution and the table of failed scalar
 * guesses beside it; the unbounded BBS98 chain and the delegation the proxy
 * minted on its own, against the same two-step path failing under AFGH; the
 * delegation graph accumulating, linking and clearing; the revocation sequence
 * and the key rotation that ends it, under both schemes; a full key
 * regeneration; the three vector tables; EVERY disclosure the page ships,
 * counted against the number it ships; three hover states; and three focus
 * rings. All of it at desktop width and again at 380px.
 *
 * See `gate.ts` for why nothing is injected into the page (the old fleet gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion block,
 * so the rendering reduced-motion readers get was never the one scanned), why
 * no panel is revealed from script (it stripped every `[hidden]` and opened
 * every `<details>` by JS before its only scan), why the lab's defaults are
 * asserted rather than assumed, and why `violations` is not the whole oracle.
 */

test('no WCAG A/AA violations across every driven state', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page, 'dark');
  await driveAllStates(page, 'desktop');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations across every driven state at 380px', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page, 'dark');
  await driveAllStates(page, '380px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations at 280px — reflow headroom below the 320px threshold', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(REFLOW);
  await boot(page, 'dark');
  await driveAllStates(page, '320px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
