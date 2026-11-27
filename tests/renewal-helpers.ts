import { createHash } from 'node:crypto';
import { renewalImprint, type RenewalLink } from '../src/index.ts';
import { toBase64Url } from '../src/index.ts';
import type { Evidence, RenewalEvidence } from '../src/client/index.ts';
import { build, type Opts } from './token-builder.ts';

/** One CA and one signer key for every token of the renewal tests; the certificates are told apart by their validity and serial. */
export const BASE = build({ crlSign: true });
export const TRUST = [BASE.caPem];

const gts = (iso: string) => iso.replace(/[-:T]/g, '').replace(/\.\d+Z$/, 'Z');
export const sha = (...parts: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
export const HASH = sha(new TextEncoder().encode('renewal test hash'));

/** A token over `imprint` stamped at `iso` (to the second). */
export function tokenAt(imprint: Uint8Array, iso: string, o: Partial<Opts> = {}) {
  return build({
    keys: BASE.keys,
    hash: imprint,
    nonceBytes: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
    genTime: gts(iso),
    ...o,
  });
}

export interface Step {
  /** ISO time of the stamp (whole seconds). */
  at: string;
  /** Validity of the signer certificate of this link (GeneralizedTime pair). */
  validity?: [string, string];
  /** Serial number of the signer certificate (one byte). */
  serial?: number;
}

/** An honest chain over `hash`: link i stamped by the real `renewalImprint` of the links before it. */
export async function makeChain(hash: Uint8Array, steps: Step[]): Promise<RenewalLink[]> {
  const links: RenewalLink[] = [];
  for (const [i, step] of steps.entries()) {
    let imprint = hash;
    if (i > 0) {
      const r = await renewalImprint({ hash, links });
      if (!r.ok) throw new Error(`imprint: ${r.reason}`);
      imprint = r.value;
    }
    const made = tokenAt(imprint, step.at, {
      ...(step.validity ? { tsaValidity: step.validity } : {}),
      ...(step.serial === undefined ? {} : { serialRaw: Uint8Array.of(step.serial) }),
    });
    links.push({ token: made.token });
  }
  return links;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** The evidence form of a chain made by `makeChain` (the repeated facts are filled in by the caller's verification result). */
export function evidenceOf(
  hash: Uint8Array,
  links: RenewalLink[],
  facts: { genTime: string; signerNotAfter: string; policy: string }[],
): Evidence {
  const one = (i: number): RenewalEvidence => ({
    kind: 'single',
    service: 'freetsa',
    receivedAtMs: Date.parse(facts[i]!.genTime) + 1000,
    token: toBase64Url(links[i]!.token),
    policy: facts[i]!.policy,
    genTime: facts[i]!.genTime,
    signerNotAfter: facts[i]!.signerNotAfter,
  });
  const first = one(0);
  return {
    v: 1,
    ...first,
    hash: toBase64Url(hash),
    hashAlg: 'sha256',
    ...(links.length > 1 ? { renewals: links.slice(1).map((_, i) => one(i + 1)) } : {}),
  } as Evidence;
}
export { iso };
