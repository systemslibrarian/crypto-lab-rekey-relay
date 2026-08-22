import * as afgh from '../crypto/afgh';
import * as bbs98 from '../crypto/bbs98';
import { Proxy } from '../crypto/proxy';
import type { AfghKeyPair, Bbs98KeyPair, Scheme } from '../crypto/types';

/**
 * The shared world: one proxy, one cast, one scheme switch.
 *
 * The proxy is shared on purpose. Its journal is the page's persistent
 * evidence panel, and evidence that resets when you change tabs is not
 * evidence. Every panel installs keys into and transforms through this one
 * instance, so the delegation graph on the Graph tab is the real accumulated
 * record of everything the learner did anywhere on the page.
 *
 * Keys are per-session and in memory only. Nothing here is persisted, and
 * `localStorage` is written exactly once, by the anti-flash script in
 * `index.html`, with the string 'dark'.
 */

export const CAST = ['Alice', 'Bob', 'Carol', 'Dave'] as const;
export type Actor = (typeof CAST)[number];

export interface LabSnapshot {
  readonly scheme: Scheme;
  readonly message: string;
}

type Listener = () => void;

export class Lab {
  scheme: Scheme = 'bbs98';
  message = 'Board minutes, 14 March. The audit finding is confirmed.';
  readonly proxy = new Proxy();

  private bbsCast!: Record<Actor, Bbs98KeyPair>;
  private afghCast!: Record<Actor, AfghKeyPair>;
  private readonly schemeListeners: Listener[] = [];
  private readonly proxyListeners: Listener[] = [];

  constructor() {
    this.regenerate();
  }

  /** Fresh keys for everyone. Also clears the proxy — the graph belongs to a cast. */
  regenerate(): void {
    this.bbsCast = Object.fromEntries(CAST.map((n) => [n, bbs98.keygen(n)])) as Record<
      Actor,
      Bbs98KeyPair
    >;
    this.afghCast = Object.fromEntries(CAST.map((n) => [n, afgh.keygen(n)])) as Record<
      Actor,
      AfghKeyPair
    >;
    this.proxy.reset();
  }

  bbs(actor: Actor): Bbs98KeyPair {
    return this.bbsCast[actor];
  }

  afgh(actor: Actor): AfghKeyPair {
    return this.afghCast[actor];
  }

  setScheme(scheme: Scheme): void {
    if (this.scheme === scheme) return;
    this.scheme = scheme;
    for (const fn of this.schemeListeners) fn();
  }

  onSchemeChange(fn: Listener): void {
    this.schemeListeners.push(fn);
  }

  onProxyChange(fn: Listener): void {
    this.proxyListeners.push(fn);
  }

  /** Call after anything that mutates the proxy, so the persistent panel repaints. */
  proxyChanged(): void {
    for (const fn of this.proxyListeners) fn();
  }

  get schemeName(): string {
    return this.scheme === 'bbs98' ? 'BBS98' : 'AFGH';
  }

  get schemeCitation(): string {
    return this.scheme === 'bbs98'
      ? 'Blaze, Bleumer and Strauss, EUROCRYPT 1998'
      : 'Ateniese, Fu, Green and Hohenberger, NDSS 2005 (section 3.1, "A Third Attempt")';
  }
}
