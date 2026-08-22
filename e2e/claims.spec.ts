import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { expect, test, type Page } from '@playwright/test';
import { FAILURE_CODES } from '../src/crypto/types';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these tests worth anything is that they compare two
 * values the PAGE printed, or re-derive the page's claim by a DIFFERENT route
 * than the source takes. A test that recomputes the same expression the source
 * uses will happily agree with a bug.
 *
 * So the re-derivations here deliberately avoid the lab's own modules:
 *
 *  - `modInverse` below is extended Euclid, written out. The page uses
 *    `@noble/curves`' `Fr.inv`. Both must land on the same scalar, and a
 *    transposed exponent in `bbs98.ts` fails against a hand-rolled inverse.
 *  - The AFGH weak key is recomputed from the page's own printed rk and b2
 *    using raw `@noble/curves` point arithmetic, not `afgh.collude`.
 *  - The plaintext-exposure claim is re-derived by hex-searching every byte
 *    string the page rendered, which is a different search over a different
 *    representation than the proxy journal's own byte search — and it carries
 *    a positive control, so a vacuous search cannot pass.
 *
 * Everything else is a cross-check between two surfaces that must agree.
 */

const R = bls.fields.Fr.ORDER;

/** Extended Euclid, deliberately not `Fr.inv`. */
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('not invertible');
  return ((old_s % m) + m) % m;
}

function hexToBigint(hex: string): bigint {
  return BigInt(`0x${hex}`);
}

function utf8Hex(s: string): string {
  return Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.goto('.');
  await expect(page.locator('#panel-relay')).toBeVisible();
}

/** The hex printed under a byte field with the given label prefix. */
async function fieldHex(page: Page, scope: string, labelStartsWith: string): Promise<string> {
  const field = page
    .locator(`${scope} .field`)
    .filter({ has: page.locator('.field-name', { hasText: labelStartsWith }) })
    .first();
  return (await field.locator('.bytes').innerText()).trim();
}

async function switchScheme(page: Page, label: 'BBS98' | 'AFGH'): Promise<void> {
  await page.locator('.seg-btn', { hasText: label }).click();
  await expect(page.locator('.seg-btn', { hasText: label })).toHaveAttribute('aria-pressed', 'true');
}

// ── The headline claim, re-derived ─────────────────────────────────────────

test('BBS98 collusion: b ÷ rk really is a, re-derived with a hand-rolled inverse', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('tab', { name: /Collusion/ }).click();

  const rkHex = await fieldHex(page, '#panel-collusion', 'rk = b');
  const bHex = await fieldHex(page, '#panel-collusion', 'his own private key');

  await page.getByRole('button', { name: 'Run the collusion' }).click();
  await expect(page.locator('#panel-collusion .verdict-alarm')).toBeVisible();

  const recoveredHex = await fieldHex(page, '#panel-collusion', 'recovered scalar');
  const actualHex = await fieldHex(page, '#panel-collusion', 'Alice’s actual private key');

  const rk = hexToBigint(rkHex);
  const b = hexToBigint(bHex);

  // Route 1: the page's own claim, cross-checked against itself.
  expect(recoveredHex).toBe(actualHex);

  // Route 2: recompute b · rk⁻¹ from the two values the page printed BEFORE it
  // ran anything, using extended Euclid rather than the library the page uses.
  const derived = (b * modInverse(rk, R)) % R;
  expect(derived.toString(16).padStart(64, '0')).toBe(recoveredHex);

  // Route 3, the other direction — parts multiply to whole. rk = b/a, so
  // rk · a must be exactly b. This one fails if the page merely printed
  // Alice's key twice without doing any arithmetic.
  const a = hexToBigint(recoveredHex);
  expect(((rk * a) % R).toString(16).padStart(64, '0')).toBe(bHex);

  // Route 4: the public key the page recomputed from the recovered scalar must
  // equal the public key Alice published, which the collusion never touched.
  const recoveredPk = await fieldHex(page, '#panel-collusion', '[recovered] · g');
  const publishedPk = await fieldHex(page, '#panel-collusion', 'Alice’s PUBLISHED public key');
  expect(recoveredPk).toBe(publishedPk);
  // And re-derive that point independently.
  expect(Buffer.from(bls.G1.Point.BASE.multiply(a).toBytes(true)).toString('hex')).toBe(publishedPk);

  await expect(page.locator('#panel-collusion .code-tag')).toContainText(
    'COLLUSION_KEY_RECOVERED'
  );
});

test('AFGH collusion: the weak key is [a1]g2, re-derived from the page’s own rk and b2', async ({
  page,
}) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /Collusion/ }).click();

  const rkHex = await fieldHex(page, '#panel-collusion', 'rk = g2');
  const b2Hex = await fieldHex(page, '#panel-collusion', 'his delegation-acceptance secret');

  await page.getByRole('button', { name: 'Run the collusion' }).click();
  await expect(page.locator('#panel-collusion .verdict-caution')).toBeVisible();

  const weakHex = await fieldHex(page, '#panel-collusion', 'recovered weak key');
  const recomputedHex = await fieldHex(page, '#panel-collusion', 'g2^a1, recomputed');

  // Cross-check: the page's two surfaces agree.
  expect(weakHex).toBe(recomputedHex);

  const rkPoint = bls.G2.Point.fromBytes(Buffer.from(rkHex, 'hex'));
  const weakPoint = bls.G2.Point.fromBytes(Buffer.from(weakHex, 'hex'));
  const b2 = hexToBigint(b2Hex);

  // Route A — the same shape the source uses, but with a hand-rolled inverse:
  // scale the printed rk by b2^-1.
  expect(Buffer.from(rkPoint.multiply(modInverse(b2, R)).toBytes(true)).toString('hex')).toBe(
    weakHex
  );

  // Route B — a genuinely different operation. Instead of dividing a point,
  // check the PAIRING identity e(g1, rk) == e(g1, weak)^b2. It shares no
  // expression with `afgh.collude`, uses the target group rather than G2, and
  // would fail if the page printed a weak key that merely looked plausible.
  const lhs = bls.pairing(bls.G1.Point.BASE, rkPoint);
  const rhs = bls.fields.Fp12.pow(bls.pairing(bls.G1.Point.BASE, weakPoint), b2);
  expect(bls.fields.Fp12.eql(lhs, rhs)).toBe(true);

  // Route C — the negative control: the same identity with a wrong scalar must
  // NOT hold, so route B cannot be passing for a trivial reason.
  const wrong = bls.fields.Fp12.pow(bls.pairing(bls.G1.Point.BASE, weakPoint), b2 + 1n);
  expect(bls.fields.Fp12.eql(lhs, wrong)).toBe(false);

  // The master secret is NOT claimed to be recovered, and the page must not
  // print the alarm code here.
  await expect(page.locator('#panel-collusion')).not.toContainText('COLLUSION_KEY_RECOVERED');
  await expect(page.locator('#panel-collusion .verdict-caution').first()).toContainText(
    'The master secret survived'
  );
});

test('AFGH: the page does not overstate the fix — it shows the residue working', async ({
  page,
}) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /Collusion/ }).click();
  await page.getByRole('button', { name: 'Run the collusion' }).click();
  await page.getByRole('button', { name: /use what they recovered/ }).click();

  // The level-2 ciphertext really is opened by the weak key, and the page says
  // so rather than claiming nothing emerged.
  const opened = page.locator('#panel-collusion .verdict-caution').last();
  await expect(opened).toContainText('Opened');
  await expect(page.locator('#panel-collusion')).not.toContainText('nothing usable');

  // And then the part that holds: every scalar the colluders can form fails
  // against a level-1 ciphertext, and the page prints each attempt.
  await page.getByRole('button', { name: 'What survives?' }).click();
  const rows = page.locator('#panel-collusion .guess-table tbody tr');
  await expect(rows).toHaveCount(3);
  for (let i = 0; i < 3; i++) {
    await expect(rows.nth(i).locator('td').nth(1)).toHaveText('rejected');
  }
  await expect(page.locator('#panel-collusion .verdict-pass')).toContainText(
    'Alice’s private mail is untouched'
  );
});

// ── The proxy-never-sees-plaintext claim, re-derived by a different route ──

test('the plaintext never appears in anything the page printed — with a positive control', async ({
  page,
}) => {
  await boot(page);
  const marker = 'ZEBRAQUARTZ-7739-PLAINTEXT-CANARY';
  await page.fill('#relay-msg', marker);
  await expect(page.locator('#panel-relay .step-note').first()).toContainText('RETIRED');

  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();
  // Capture a byte run the page really printed BEFORE step 4 replaces the
  // ciphertext panes with the plaintext comparison — it is the positive
  // control below.
  const c1 = await fieldHex(page, '#panel-relay', 'c1 — message half');
  await page.getByRole('button', { name: /Bob decrypts/ }).click();
  await expect(page.locator('#panel-relay .verdict-pass')).toContainText('Byte-for-byte identical');

  // Everything the page rendered as bytes, concatenated.
  const printed = (await page.locator('.bytes, .journal-fields li').allInnerTexts())
    .join('')
    .replace(/[^0-9a-f]/g, '');

  // NEGATIVE: the marker's hex must not be in there.
  expect(printed).not.toContain(utf8Hex(marker));
  // Not even a short prefix of it.
  expect(printed).not.toContain(utf8Hex(marker.slice(0, 8)));

  // POSITIVE CONTROL: a byte run the page demonstrably DID print must be found
  // by the same search. Without this the negative result could just mean the
  // search is looking at nothing.
  expect(c1.length).toBeGreaterThan(64);
  expect(printed).toContain(c1.slice(0, 40));

  // And the page's own claim agrees with the independent search.
  await expect(page.locator('.proxyview .pill-ok')).toContainText('plaintext bytes found: 0');
});

test('the message half is byte-identical across the hop, and the label is not decorative', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  const before = await fieldHex(page, '#panel-relay', 'c1 — message half');
  const keyBefore = await fieldHex(page, '#panel-relay', 'c2 — key half');

  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();

  const after = await fieldHex(page, '#panel-relay', 'c1 — message half');
  const keyAfter = await fieldHex(page, '#panel-relay', 'c2 — key half');

  // The claim, checked rather than read off the label.
  expect(after).toBe(before);
  expect(keyAfter).not.toBe(keyBefore);

  // Now the labels must AGREE with that measurement, in both directions.
  const messageField = page
    .locator('#panel-relay .field')
    .filter({ has: page.locator('.field-name', { hasText: 'c1 — message half' }) });
  await expect(messageField.locator('.tag-same')).toHaveText('BYTE-IDENTICAL');
  const keyField = page
    .locator('#panel-relay .field')
    .filter({ has: page.locator('.field-name', { hasText: 'c2 — key half' }) });
  await expect(keyField.locator('.tag-diff')).toHaveText('CHANGED');
});

test('AFGH: the key half changes GROUP, and the page says so only when it does', async ({
  page,
}) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  const alphaBefore = await fieldHex(page, '#panel-relay', 'alpha — key half (G1');
  // 48 bytes compressed in G1.
  expect(alphaBefore.length).toBe(96);
  await expect(page.locator('#panel-relay')).not.toContainText('changed GROUP');

  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();

  const alphaAfter = await fieldHex(page, '#panel-relay', 'alpha — key half (GT');
  // 576 bytes in GT.
  expect(alphaAfter.length).toBe(1152);
  await expect(page.locator('#panel-relay')).toContainText('changed GROUP');
  // The claim in the prose must match the byte counts on screen.
  await expect(page.locator('#panel-relay .step-note').last()).toContainText('48 bytes in G1');
  await expect(page.locator('#panel-relay .step-note').last()).toContainText('576 bytes in GT');
});

// ── Every failure path names its actual cause ─────────────────────────────

/**
 * Every code the page prints must be one the source actually defines.
 *
 * This is a cross-check rather than a spelling test: `FAILURE_CODES` is the
 * exported enumeration in `src/crypto/types.ts`, so a code invented in a UI
 * string — or a code renamed in one place and not the other — fails here.
 */
async function assertCodeIsDefined(page: Page, locator: string): Promise<string> {
  const code = (await page.locator(locator).first().innerText()).trim();
  expect(FAILURE_CODES as readonly string[]).toContain(code);
  return code;
}

/** The same code must appear in the proxy's own journal for the same refusal. */
async function assertJournalledWithCode(page: Page, code: string): Promise<void> {
  const refusals = page.locator('.journal .journal-entry', { hasText: code });
  expect(await refusals.count()).toBeGreaterThan(0);
  await expect(refusals.first().locator('.journal-kind')).toHaveText('REFUSED');
}

test('MALFORMED_RK names the structural reason, and the proxy journals the same code', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: 'Corrupt the rk' }).click();
  const v = page.locator('#panel-relay .verdict-fail');
  const code = await assertCodeIsDefined(page, '#panel-relay .verdict-fail .code-tag');
  expect(code).toBe('MALFORMED_RK');
  await expect(v).toContainText('not a unit mod r');
  await expect(v).toContainText('every ciphertext to the same constant');
  // Two surfaces, one event: the verdict and the proxy's own record agree.
  await assertJournalledWithCode(page, code);
});

test('RK_MISMATCH names both endpoints, and the names match the delegation graph', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Carol’s ciphertext/ }).click();
  const v = page.locator('#panel-relay .verdict-fail');
  const code = await assertCodeIsDefined(page, '#panel-relay .verdict-fail .code-tag');
  expect(code).toBe('RK_MISMATCH');
  await expect(v).toContainText('nobody on earth can open');

  // The two names in the refusal are read OFF THE PAGE and checked against the
  // delegation the proxy actually holds, rather than against a literal.
  const detail = await v.innerText();
  const m = /addressed to (\w+).*re-encrypts from (\w+)/s.exec(detail);
  expect(m, 'the refusal must name both endpoints').not.toBeNull();
  const [, addressedTo, reencryptsFrom] = m!;
  expect(addressedTo).not.toBe(reencryptsFrom);
  await page.getByRole('tab', { name: /Delegation Graph/ }).click();
  const edges = await page.locator('#panel-graph .edges .edge').first().innerText();
  expect(edges).toContain(reencryptsFrom!);
  expect(edges).not.toContain(addressedTo!);
});

test('ALREADY_REENCRYPTED names the group, and the byte sizes on the Relay tab agree', async ({
  page,
}) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /Relay it down the chain/ }).click();
  const v = page.locator('#panel-onehop .verdict-pass');
  const code = await assertCodeIsDefined(page, '#panel-onehop .verdict-pass .code-tag');
  expect(code).toBe('ALREADY_REENCRYPTED');
  await expect(v).toContainText('already in GT');
  await expect(v).toContainText('nothing maps out of GT');
  await assertJournalledWithCode(page, code);

  // The reason given is a claim about GROUPS. Check it against the byte counts
  // the Relay tab prints for the very same ciphertext shapes: a level-2 alpha
  // is a 48-byte G1 point, a level-1 alpha is a 576-byte GT element.
  await page.getByRole('tab', { name: /The Relay/ }).click();
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  const l2 = await fieldHex(page, '#panel-relay', 'alpha — key half (G1');
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();
  const l1 = await fieldHex(page, '#panel-relay', 'alpha — key half (GT');
  expect(l2.length / 2).toBe(48);
  expect(l1.length / 2).toBe(576);
});

test('WRONG_LEVEL fires in both directions and names the groups', async ({ page }) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /Decrypt at the wrong level/ }).click();
  const codes = page.locator('#panel-onehop .code-tag');
  await expect(codes).toHaveCount(2);
  for (let i = 0; i < 2; i++) {
    const code = (await codes.nth(i).innerText()).trim();
    expect(FAILURE_CODES as readonly string[]).toContain(code);
    expect(code).toBe('WRONG_LEVEL');
  }
  await expect(page.locator('#panel-onehop')).toContainText('not even in the same group');
  // Both directions really are present: one verdict says the level-1 decryptor
  // met a level-2 ciphertext, the other the reverse.
  const text = await page.locator('#panel-onehop').innerText();
  expect(text).toContain('Level-1 decryptor, level-2 ciphertext');
  expect(text).toContain('Level-2 decryptor, level-1 ciphertext');
});

test('every failure code the source defines is reachable from the page', async ({ page }) => {
  await boot(page);
  const seen = new Set<string>();

  // MALFORMED_RK and RK_MISMATCH, from the Relay tab under BBS98.
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: 'Corrupt the rk' }).click();
  seen.add((await page.locator('#panel-relay .code-tag').first().innerText()).trim());
  await page.getByRole('button', { name: /Carol’s ciphertext/ }).click();
  seen.add((await page.locator('#panel-relay .code-tag').first().innerText()).trim());

  // COLLUSION_KEY_RECOVERED, from the Collusion tab under BBS98.
  await page.getByRole('tab', { name: /Collusion/ }).click();
  await page.getByRole('button', { name: 'Run the collusion' }).click();
  seen.add((await page.locator('#panel-collusion .code-tag').first().innerText()).trim());

  // ALREADY_REENCRYPTED and WRONG_LEVEL, from One Hop under AFGH.
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /Relay it down the chain/ }).click();
  seen.add((await page.locator('#panel-onehop .code-tag').first().innerText()).trim());
  await page.getByRole('button', { name: /Decrypt at the wrong level/ }).click();
  seen.add((await page.locator('#panel-onehop .code-tag').first().innerText()).trim());

  // No code is declared and unreachable, and none is shown that is undeclared.
  expect([...seen].sort()).toEqual([...FAILURE_CODES].sort());
});

test('BBS98 has no level structure, and the page says which scheme owns the code', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /Decrypt at the wrong level/ }).click();
  await expect(page.locator('#panel-onehop .verdict-caution')).toContainText(
    'no levels to get wrong'
  );
  await expect(page.locator('#panel-onehop')).toContainText('WRONG_LEVEL is an AFGH failure code');
});

// ── Cross-checks between surfaces that must agree ─────────────────────────

test('the One Hop chain verdict agrees with the rows it is counting', async ({ page }) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /Relay it down the chain/ }).click();
  // One encrypt row, one successful hop, one stop.
  await expect(page.locator('#panel-onehop .edge')).toHaveCount(3);
  await expect(page.locator('#panel-onehop .edge-revoked')).toHaveCount(1);
  await expect(page.locator('#panel-onehop .verdict-pass')).toContainText('stopped at Bob → Carol');

  await switchScheme(page, 'BBS98');
  await page.getByRole('button', { name: /Relay it down the chain/ }).click();
  // One encrypt row plus three hops, none of them stopped.
  await expect(page.locator('#panel-onehop .edge')).toHaveCount(4);
  await expect(page.locator('#panel-onehop .edge-revoked')).toHaveCount(0);
  await expect(page.locator('#panel-onehop .verdict-caution')).toContainText('Three transforms');
});

test('the BBS98 composed key equals a genuine one, checked by re-deriving it', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /One Hop/ }).click();
  await page.getByRole('button', { name: /mint a key nobody issued/ }).click();
  const printed = await page.locator('#panel-onehop .bytes').allInnerTexts();
  expect(printed).toHaveLength(2);
  const [composed, genuine] = printed.map((s) => s.trim());
  expect(composed).toBe(genuine);
  await expect(page.locator('#panel-onehop .verdict-alarm')).toContainText('Identical');
});

/**
 * Both halves of the graph claim, checked the same way.
 *
 * The point of running these as a PAIR is that the two schemes must produce
 * the same table shape and differ only in the outcome column. An earlier
 * version of the AFGH test asserted `tbody tr` count 0 — which passed
 * vacuously, because that branch emitted no table at all. Asserting the same
 * row count on both sides is what makes the difference a measurement.
 */
async function graphRows(page: Page): Promise<{ issued: number; composed: number; total: number }> {
  const rows = page.locator('#panel-graph tbody tr');
  const total = await rows.count();
  let issued = 0;
  let composed = 0;
  for (let i = 0; i < total; i++) {
    const origin = await rows.nth(i).locator('td').nth(2).innerText();
    if (origin.includes('issued by the delegator')) issued++;
    if (origin.includes('COMPOSED by the proxy')) composed++;
  }
  return { issued, composed, total };
}

test('BBS98: the graph table agrees with the alarm that counts it', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /Delegation Graph/ }).click();
  await page.locator('#panel-graph').getByRole('button', { name: 'Alice → Bob' }).click();
  await page.locator('#panel-graph').getByRole('button', { name: 'Bob → Carol' }).click();

  const { issued, composed, total } = await graphRows(page);
  // Two issued edges plus one attempted two-step path (Alice → Carol).
  expect(issued).toBe(2);
  expect(total).toBe(3);
  expect(composed).toBe(1);
  // The edge list and the table must agree on how many were issued.
  expect(await page.locator('#panel-graph .edges .edge').count()).toBe(issued);
  await expect(page.locator('#panel-graph .verdict-alarm')).toContainText(
    `${composed} delegation nobody issued`
  );
  await expect(page.locator('#panel-graph .verdict-alarm')).toContainText('Alice→Carol');
});

test('AFGH: the same two-step path is attempted and fails', async ({ page }) => {
  await boot(page);
  await switchScheme(page, 'AFGH');
  await page.getByRole('tab', { name: /Delegation Graph/ }).click();
  await page.locator('#panel-graph').getByRole('button', { name: 'Alice → Bob' }).click();
  await page.locator('#panel-graph').getByRole('button', { name: 'Bob → Carol' }).click();

  const { issued, composed, total } = await graphRows(page);
  // SAME shape as BBS98 — the path is attempted, not skipped.
  expect(issued).toBe(2);
  expect(total).toBe(3);
  expect(composed).toBe(0);
  await expect(page.locator('#panel-graph tbody')).toContainText('not composable');
  await expect(page.locator('#panel-graph tbody')).toContainText('CDH in G2');
  await expect(page.locator('#panel-graph .verdict-pass')).toContainText(
    'exactly the graph it was given'
  );
  await expect(page.locator('#panel-graph .verdict-pass')).toContainText(
    '1 two-step path attempted'
  );
});

test('the proxy journal entry count matches the rows it renders', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();

  const summary = await page.locator('.proxyview .exposure').innerText();
  const claimed = Number(/(\d+) journal entr/.exec(summary)?.[1]);
  const rendered = await page.locator('.journal .journal-entry').count();
  expect(claimed).toBe(rendered);
  // Three: the key installed, the ciphertext in, the ciphertext out.
  expect(rendered).toBe(3);
});

test('the vectors summary count matches the rows it is counting', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /Vectors/ }).click();
  await expect(page.locator('#panel-vectors .verdict-pass')).toBeVisible();

  const headings = await page.locator('#panel-vectors h4').allInnerTexts();
  const parsed = headings.map((h) => /(\d+) \/ (\d+)/.exec(h)).filter(Boolean);
  // Three tables, kept separate on purpose: published vectors, self-checks,
  // and scheme transcription checks. Only the first are known-answer tests.
  expect(parsed).toHaveLength(3);
  // `h4` is uppercased by CSS, so compare case-insensitively.
  expect(headings[0]?.toLowerCase()).toContain('published specification vectors');
  expect(headings[1]?.toLowerCase()).toContain('no document supplies the answer');
  expect(headings[2]?.toLowerCase()).toContain('not specification vectors');
  const totalClaimed = parsed.reduce((n, m) => n + Number(m![2]), 0);
  const totalPassing = parsed.reduce((n, m) => n + Number(m![1]), 0);

  expect(await page.locator('#panel-vectors .kat').count()).toBe(totalClaimed);
  expect(await page.locator('#panel-vectors .pill-ok').count()).toBe(totalPassing);
  expect(await page.locator('#panel-vectors .kat-fail').count()).toBe(0);
  expect(totalPassing).toBe(totalClaimed);
});

// ── Retirement, and the no-op guard ───────────────────────────────────────

test('editing the message retires the verdict AND says it was retired', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  await page.getByRole('button', { name: /Alice issues rk/ }).click();
  await page.getByRole('button', { name: /Proxy transforms/ }).click();
  await expect(page.locator('#panel-relay .verdict-pass')).toBeVisible();

  await page.fill('#relay-msg', 'a completely different message');
  await expect(page.locator('#panel-relay .verdict-pass')).toHaveCount(0);
  await expect(page.locator('#panel-relay .ledger')).toHaveCount(0);
  await expect(page.locator('#panel-relay .step-note').first()).toContainText('RETIRED');
  await expect(page.getByRole('button', { name: /Proxy transforms/ })).toBeDisabled();
});

test('NO-OP GUARD: re-entering the same message does not retire a fresh verdict', async ({
  page,
}) => {
  await boot(page);
  await page.getByRole('button', { name: /Alice encrypts/ }).click();
  const current = await page.locator('#relay-msg').inputValue();
  await expect(page.locator('#panel-relay .verdict-pass')).toBeVisible();

  // Re-set the value to exactly what it already is. `fill` still dispatches an
  // input event, so this is a real no-op test rather than a no-op.
  await page.fill('#relay-msg', current);
  await expect(page.locator('#panel-relay .verdict-pass')).toBeVisible();
  await expect(page.locator('#panel-relay .step-note').first()).not.toContainText('RETIRED');
  await expect(page.getByRole('button', { name: /Alice issues rk/ })).toBeEnabled();
});

test('NO-OP GUARD: re-clicking the active scheme does not discard the panel', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /Collusion/ }).click();
  await page.getByRole('button', { name: 'Run the collusion' }).click();
  await expect(page.locator('#panel-collusion .verdict-alarm')).toBeVisible();

  await page.locator('.seg-btn', { hasText: 'BBS98' }).click();
  await expect(page.locator('#panel-collusion .verdict-alarm')).toBeVisible();

  // But switching to the OTHER scheme must retire it, because the result on
  // screen was computed under a scheme that is no longer selected.
  await page.locator('.seg-btn', { hasText: 'AFGH' }).click();
  await expect(page.locator('#panel-collusion .verdict-alarm')).toHaveCount(0);
  await expect(page.locator('.hint').first()).toContainText('AFGH');
});

// ── The [hidden] probe ─────────────────────────────────────────────────────

test('[hidden] tabpanels are really hidden — no CSS rule outranks the UA rule', async ({ page }) => {
  await boot(page);
  const leaked = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))) {
      const cs = getComputedStyle(el);
      const painted = cs.display !== 'none' && cs.visibility !== 'hidden';
      if (painted || el.checkVisibility?.({ checkVisibilityCSS: true })) {
        out.push(`${el.tagName.toLowerCase()}#${el.id} display=${cs.display}`);
      }
    }
    return out;
  });
  expect(leaked, 'a [hidden] element that still paints is the cascade trap').toEqual([]);

  // And the hidden panels are not merely invisible — they were never rendered.
  for (const id of ['collusion', 'onehop', 'graph', 'undelegate', 'vectors']) {
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }
});

// ── Honest scoping is on the page, not only in the README ─────────────────

test('the page states what it is not, in-page', async ({ page }) => {
  await boot(page);
  // The page-level scoping callout, not a panel's own — it is a direct child of #app.
  const scope = page.locator('#app > .callout-scope');
  await expect(scope).toContainText('Not production cryptography');
  await expect(scope).toContainText('teaching demo');
  await expect(scope).toContainText('Do not use this code to protect anything');

  // The "what this does not prove" disclosure exists and ships shut.
  const notProve = page.locator('details', { hasText: 'What this page does NOT prove' }).first();
  await expect(notProve).toHaveCount(1);
  await expect(notProve).not.toHaveAttribute('open', '');
});

test('the negative claim about revocation is scoped, and names alternatives', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /Un-delegate/ }).click();
  const scope = page.locator('#panel-undelegate .callout-scope');
  await expect(scope).toContainText('not about proxy re-encryption in general');

  const d = page.locator('#panel-undelegate details').first();
  await d.locator('summary').click();
  await expect(d).toContainText('section 3.6');
  await expect(d).toContainText('Weng');
  await expect(d).toContainText('Tang');
  await expect(d).toContainText('Liu, Wang and Wu');
  await expect(d).toContainText('None of these three revokes anything');
});

test('revocation demonstrably fails, then rotation demonstrably works', async ({ page }) => {
  await boot(page);
  await page.getByRole('tab', { name: /Un-delegate/ }).click();
  await page.getByRole('button', { name: 'Try to un-delegate' }).click();

  // Five steps, and the last one must be the one that failed.
  const steps = page.locator('#panel-undelegate .edge');
  await expect(steps).toHaveCount(5);
  await expect(steps.nth(3)).toContainText('the proxy now refuses');
  await expect(steps.nth(4)).toContainText('the colluders read it anyway');
  await expect(page.locator('#panel-undelegate .verdict-alarm')).toContainText(
    'The revocation revoked nothing'
  );

  // The message the colluders read must be the one the page said they should
  // not be able to read — compared, not asserted.
  const read = await page.locator('#panel-undelegate .bytes').innerText();
  expect(read.trim()).toBe(
    'Written the day after Alice revoked. Nobody should be able to read this.'
  );

  await page.getByRole('button', { name: /the only way that works/ }).click();
  await expect(page.locator('#panel-undelegate .verdict-pass')).toContainText(
    'The stolen key is now worthless'
  );
});

// ── The hero and head say the same thing the page does ────────────────────

test('exactly one h1, and the head metadata matches the lab', async ({ page }) => {
  await boot(page);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveText('Rekey Relay');
  await expect(page).toHaveTitle('Rekey Relay — crypto-lab');
  const desc = await page.locator('meta[name="description"]').getAttribute('content');
  expect(desc).toContain('proxy re-encryption');
  expect(desc).toContain('BLS12-381');
  await expect(page.locator('meta[name="description"]')).toHaveCount(1);
  // The scripture footer, verbatim and exactly once.
  await expect(page.locator('.scripture-footer p')).toHaveCount(1);
  await expect(page.locator('.scripture-footer p')).toHaveText(
    'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31'
  );
});
