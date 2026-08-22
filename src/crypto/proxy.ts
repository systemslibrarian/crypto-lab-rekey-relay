import {
  bytesToHex,
  g1ToBytes,
  g2FromBytes,
  g2ToBytes,
  gtToBytes,
  isValidScalar,
  scalarToBytes,
  type G1Point,
} from './group';
import * as bbs98 from './bbs98';
import * as afgh from './afgh';
import {
  fail,
  ok,
  type AnyCiphertext,
  type AnyReKey,
  type Outcome,
  type Scheme,
} from './types';

/**
 * The proxy, instrumented.
 *
 * The claim a proxy re-encryption demo has to earn is "the proxy never learns
 * the plaintext." Asserting it in a caption is worthless, and printing a wall
 * of hex to imply it is worse — a learner cannot tell whether the hex contains
 * the message or not, which is exactly the question.
 *
 * So this module makes the claim MEASURABLE. Every byte the proxy is handed
 * goes into `journal` before it is used, tagged with where it came from. The
 * page renders that journal verbatim as the proxy's view, and
 * `findPlaintextExposure` searches the whole journal for the learner's actual
 * message bytes. The panel's "plaintext bytes seen: 0" is the RESULT of that
 * search over everything on record, not a constant.
 *
 * `test/proxy.test.ts` runs the same search after a full delegate-transform-
 * decrypt round trip, so the property is a passing test and not a promise.
 */

export type JournalKind =
  | 'rekey-installed'
  | 'rekey-revoked'
  | 'ciphertext-in'
  | 'ciphertext-out'
  | 'refused';

export interface JournalEntry {
  readonly seq: number;
  readonly kind: JournalKind;
  /** Human-readable summary. Never contains message content. */
  readonly summary: string;
  /** Every field the proxy touched, as it saw it. */
  readonly fields: readonly { readonly name: string; readonly hex: string }[];
  /** The raw bytes behind `fields`, kept for the exposure search. */
  readonly bytes: readonly Uint8Array[];
  readonly refusalCode?: string;
}

export interface DelegationEdge {
  readonly id: string;
  readonly scheme: Scheme;
  readonly from: string;
  readonly to: string;
  readonly installedAt: number;
  readonly revoked: boolean;
  /** Transforms performed under this edge. */
  readonly uses: number;
}

export class Proxy {
  private readonly keys = new Map<string, AnyReKey>();
  private readonly edges = new Map<string, DelegationEdge>();
  private readonly entries: JournalEntry[] = [];
  private seq = 0;
  private clock = 0;

  /** Everything the proxy has on record, oldest first. */
  get journal(): readonly JournalEntry[] {
    return this.entries;
  }

  get delegations(): readonly DelegationEdge[] {
    return [...this.edges.values()];
  }

  reset(): void {
    this.keys.clear();
    this.edges.clear();
    this.entries.length = 0;
    this.seq = 0;
    this.clock = 0;
  }

  edgeId(scheme: Scheme, from: string, to: string): string {
    return `${scheme}:${from}->${to}`;
  }

  /**
   * Install a re-encryption key.
   *
   * The proxy validates structurally and records the EDGE. Note what it now
   * knows that it did not know before: that `from` delegates to `to`. It never
   * learns a message, and it always learns the graph. Whether that trade is
   * acceptable is a deployment question, and for a lot of deployments the
   * answer is no.
   */
  install(rk: AnyReKey): Outcome<DelegationEdge> {
    const id = this.edgeId(rk.scheme, rk.fromLabel, rk.toLabel);
    const validation = validateReKey(rk);
    if (!validation.ok) {
      this.record('refused', `refused a re-encryption key from ${rk.fromLabel}`, rkFields(rk), validation.code);
      return fail(validation.code, validation.detail);
    }
    this.keys.set(id, rk);
    const edge: DelegationEdge = {
      id,
      scheme: rk.scheme,
      from: rk.fromLabel,
      to: rk.toLabel,
      installedAt: ++this.clock,
      revoked: false,
      uses: 0,
    };
    this.edges.set(id, edge);
    this.record('rekey-installed', `${rk.fromLabel} delegates to ${rk.toLabel}`, rkFields(rk));
    return ok(edge);
  }

  /**
   * Delete a re-encryption key.
   *
   * This is the ONLY revocation either scheme on this page offers, and it is
   * not cryptographic: it works exactly as long as the proxy chooses to honour
   * it. The edge stays in the graph, marked revoked, because a proxy that
   * deleted the record would also be a proxy that could have kept the key.
   */
  revoke(id: string): boolean {
    const edge = this.edges.get(id);
    if (!edge || edge.revoked) return false;
    const rk = this.keys.get(id);
    this.keys.delete(id);
    this.edges.set(id, { ...edge, revoked: true });
    this.record(
      'rekey-revoked',
      `${edge.from} withdrew the delegation to ${edge.to}`,
      rk ? rkFields(rk) : []
    );
    return true;
  }

  hasKey(id: string): boolean {
    return this.keys.has(id);
  }

  getKey(id: string): AnyReKey | undefined {
    return this.keys.get(id);
  }

  /**
   * Transform a ciphertext under an installed key.
   *
   * The ciphertext is journalled BEFORE the transform and the result AFTER, so
   * the exposure search sees exactly what crossed the boundary in both
   * directions — including on the paths that refuse.
   */
  transform(id: string, ct: AnyCiphertext): Outcome<AnyCiphertext> {
    const rk = this.keys.get(id);
    this.record('ciphertext-in', `received a ${ct.scheme} ciphertext to transform`, ctFields(ct));
    if (!rk) {
      const known = [...this.keys.keys()].join(', ') || 'none';
      this.record('refused', `no key installed for ${id}`, [], 'RK_MISMATCH');
      return fail('RK_MISMATCH', `no re-encryption key installed for ${id} (installed: ${known})`);
    }
    if (rk.scheme !== ct.scheme) {
      this.record('refused', `scheme mismatch for ${id}`, [], 'RK_MISMATCH');
      return fail('RK_MISMATCH', `a ${rk.scheme} key cannot transform a ${ct.scheme} ciphertext`);
    }

    const result: Outcome<AnyCiphertext> =
      rk.scheme === 'bbs98'
        ? bbs98.reencrypt(ct as Parameters<typeof bbs98.reencrypt>[0], rk)
        : afgh.reencrypt(ct as Parameters<typeof afgh.reencrypt>[0], rk);

    if (!result.ok) {
      this.record('refused', `refused: ${result.code}`, [], result.code);
      return result;
    }
    const edge = this.edges.get(id);
    if (edge) this.edges.set(id, { ...edge, uses: edge.uses + 1 });
    this.record('ciphertext-out', `transformed and forwarded to ${rk.toLabel}`, ctFields(result.value));
    return result;
  }

  private record(
    kind: JournalKind,
    summary: string,
    fields: { name: string; bytes: Uint8Array }[],
    refusalCode?: string
  ): void {
    this.entries.push({
      seq: ++this.seq,
      kind,
      summary,
      fields: fields.map((f) => ({ name: f.name, hex: bytesToHex(f.bytes) })),
      bytes: fields.map((f) => f.bytes),
      ...(refusalCode ? { refusalCode } : {}),
    });
  }

  /**
   * Search everything on record for a byte sequence.
   *
   * Returns the journal entry and offset of the first occurrence, or null. The
   * page calls this with the learner's own message; a hit would mean the demo
   * is lying, and the panel says so in those words.
   */
  findPlaintextExposure(needle: Uint8Array): { seq: number; field: string; offset: number } | null {
    if (needle.length === 0) return null;
    for (const entry of this.entries) {
      for (let i = 0; i < entry.bytes.length; i++) {
        const hay = entry.bytes[i]!;
        const at = indexOfBytes(hay, needle);
        if (at >= 0) {
          return { seq: entry.seq, field: entry.fields[i]?.name ?? `field ${i}`, offset: at };
        }
      }
    }
    return null;
  }

  /** Total bytes the proxy has handled — the denominator for the exposure claim. */
  bytesHandled(): number {
    let n = 0;
    for (const e of this.entries) for (const b of e.bytes) n += b.length;
    return n;
  }
}

// ── helpers ────────────────────────────────────────────────────────────────

function indexOfBytes(hay: Uint8Array, needle: Uint8Array): number {
  if (needle.length > hay.length) return -1;
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Structural validation of a re-encryption key, before it is stored or used.
 *
 * BBS98's key is a scalar, so the check is range: 0 has no inverse and would
 * map every ciphertext onto the identity. AFGH's key is a point, so the check
 * is the wire encoding — `fromBytes` rejects off-curve points and points
 * outside the order-r subgroup, both of which are how a small-subgroup attack
 * starts.
 */
function validateReKey(rk: AnyReKey): { ok: true } | { ok: false; code: 'MALFORMED_RK'; detail: string } {
  if (rk.scheme === 'bbs98') {
    if (!isValidScalar(rk.value)) {
      return { ok: false, code: 'MALFORMED_RK', detail: `scalar ${rk.value} is not a unit mod r` };
    }
    return { ok: true };
  }
  try {
    // Round-trip through the wire encoding, because a real proxy receives
    // bytes rather than objects. `g2FromBytes` rejects anything off-curve or
    // outside the order-r subgroup; the identity is rejected separately since
    // it is a perfectly valid point that maps every ciphertext to a constant.
    const bytes = g2ToBytes(rk.value);
    if (bytes.length !== 96) throw new Error(`expected 96 compressed bytes, got ${bytes.length}`);
    const parsed = g2FromBytes(bytes);
    if (parsed.is0()) throw new Error('identity point re-encrypts every ciphertext to a constant');
  } catch (e) {
    return { ok: false, code: 'MALFORMED_RK', detail: (e as Error).message };
  }
  return { ok: true };
}

/**
 * Serialize for the journal without ever throwing.
 *
 * A refused key can be exactly the kind of value that has no valid encoding —
 * the G2 identity is the case that found this: @noble/curves refuses to
 * serialize it ("bad point: ZERO"), which is correct, and would have taken the
 * journalling of the refusal down with it. The journal has to survive the very
 * inputs it exists to record, so an unserializable field is recorded as such.
 */
function safeBytes(name: string, f: () => Uint8Array): { name: string; bytes: Uint8Array } {
  try {
    return { name, bytes: f() };
  } catch {
    return { name: `${name} (no valid encoding)`, bytes: new Uint8Array(0) };
  }
}

function rkFields(rk: AnyReKey): { name: string; bytes: Uint8Array }[] {
  return rk.scheme === 'bbs98'
    ? [
        { name: 'rk (scalar mod r)', bytes: scalarToBytes(rk.value) },
        { name: 'pk_from', bytes: g1ToBytes(rk.from) },
        { name: 'pk_to', bytes: g1ToBytes(rk.to) },
      ]
    : [
        safeBytes('rk (point in G2)', () => g2ToBytes(rk.value)),
        safeBytes('Z^a1 of delegator', () => gtToBytes(rk.from.Za1)),
        safeBytes('g2^a2 of delegatee', () => g2ToBytes(rk.to.Ga2)),
      ];
}

function ctFields(ct: AnyCiphertext): { name: string; bytes: Uint8Array }[] {
  // Every field goes through `safeBytes`, for exactly the reason `rkFields`
  // does: the journal is written BEFORE any validation, so it is handed the
  // malformed inputs it exists to record. @noble refuses to encode the identity
  // point and refuses to encode a point outside the order-r subgroup, and a
  // journal that throws on those would take the refusal down with it — turning
  // a named `Outcome` failure into an uncaught exception at the one boundary
  // whose whole job is to fail closed.
  if (ct.scheme === 'bbs98') {
    return [
      safeBytes('c1 (message half, G1)', () => g1ToBytes(ct.c1)),
      safeBytes('c2 (key half, G1)', () => g1ToBytes(ct.c2)),
      { name: 'AES-GCM nonce', bytes: ct.payload.iv },
      { name: 'AES-GCM ciphertext+tag', bytes: ct.payload.ct },
    ];
  }
  if (ct.level === 2) {
    return [
      safeBytes('alpha = g1^k (level 2, G1)', () => g1ToBytes(ct.alpha)),
      safeBytes('beta (message half, GT)', () => gtToBytes(ct.beta)),
      { name: 'AES-GCM nonce', bytes: ct.payload.iv },
      { name: 'AES-GCM ciphertext+tag', bytes: ct.payload.ct },
    ];
  }
  return [
    safeBytes('alpha (level 1, GT)', () => gtToBytes(ct.alpha)),
    safeBytes('beta (message half, GT)', () => gtToBytes(ct.beta)),
    { name: 'AES-GCM nonce', bytes: ct.payload.iv },
    { name: 'AES-GCM ciphertext+tag', bytes: ct.payload.ct },
  ];
}

export function shortHex(hex: string, head = 10, tail = 6): string {
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** Re-exported so the UI can print a G1 point without importing group.ts. */
export function pkHex(p: G1Point): string {
  return bytesToHex(g1ToBytes(p));
}
