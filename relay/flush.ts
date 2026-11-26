import { toBase64Url } from '../src/index.ts';
import { buildBatch } from './batch.ts';
import type { createObtain } from './obtain.ts';
import type { Reply, Waiting, Window } from './planner.ts';
import type { RelayContext } from './types.ts';

export const LAPSED: Reply = { status: 401, body: { error: 'unauthorized' }, unsent: true };

export const answerAll = (waiting: readonly Waiting[], reply: Reply): void => {
  for (const w of waiting) w.resolve(reply);
};

/** The window is stamped: salts, tree (blinded leaves, shuffled order), one stamp for the imprint, a receipt for each request. */
export function createFlush(ctx: RelayContext, obtainer: ReturnType<typeof createObtain>) {
  const { options, stats } = ctx;
  const { obtain, stampBody } = obtainer;
  /** An integer 0 <= x < m from the relay's random source, without bias (rejection sampling). */
  function randomBelow(m: number): number {
    const limit = Math.floor(0x1_0000_0000 / m) * m;
    for (let attempt = 0; attempt < 64; attempt += 1) {
      const b = options.random(4);
      if (b.length !== 4) throw new Error('random source gave the wrong length');
      const v = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
      if (v < limit) return v % m;
    }
    throw new Error('random source does not spread');
  }

  /** The tree order: a Fisher-Yates shuffle, so the order of the leaves tells nothing about the order of arrival. */
  function shuffled(n: number): number[] {
    const order = Array.from({ length: n }, (_, i) => i);
    for (let i = n - 1; i > 0; i -= 1) {
      const j = randomBelow(i + 1);
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    return order;
  }

  /** One window: salts, tree, one stamp for the imprint, and a receipt for each waiting request. */
  async function flush(w: Window): Promise<void> {
    // a request whose key lapsed while the window was open is out of the tree (and answered 401); nothing left, no call
    const waiting = w.waiting.filter((x) => {
      if (x.valid()) return true;
      x.resolve(LAPSED);
      return false;
    });
    if (waiting.length === 0) return;
    const entries = waiting.map((x) => {
      const salt = options.random(32);
      if (salt.length !== 32) throw new Error('random source gave the wrong length');
      return { hash: x.hash, salt: new Uint8Array(salt) };
    });
    const built = buildBatch(entries, shuffled(waiting.length));
    const got = await obtain(w.service, new Uint8Array(built.imprint), w.creds);
    if (!got.ok) return answerAll(waiting, { status: got.status, body: got.body });
    stats.stamped += 1;
    stats.batched = (stats.batched ?? 0) + waiting.length;
    const base = stampBody(w.service, got);
    waiting.forEach((x, i) => {
      const proof = built.proofs[i]!;
      x.resolve({
        status: 200,
        body: {
          ...base,
          batch: {
            v: 1,
            size: proof.size,
            index: proof.index,
            salt: toBase64Url(entries[i]!.salt),
            path: proof.path.map((node) => toBase64Url(new Uint8Array(node))),
          },
        },
      });
    });
  }

  return { flush };
}
