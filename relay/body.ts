import type { IncomingMessage } from 'node:http';
import { fromBase64Url } from '../src/index.ts';
import { RELAY_LIMITS } from './limits.ts';

export const JSON_TYPE = 'application/json';
/** The member sets of a JSON body (sorted, joined by a comma): `hash`, plus `mode` and `upstream` when given. */
const BODY_KEYS = ['hash', 'hash,mode', 'hash,upstream', 'hash,mode,upstream'];

/** The client went away while its body was coming: nobody is left to answer. */
export class ClientAborted extends Error {}

export async function readBody(req: IncomingMessage): Promise<Uint8Array | null> {
  const declared = req.headers['content-length'];
  if (declared !== undefined && Number(declared) > RELAY_LIMITS.bodyBytes) return null;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > RELAY_LIMITS.bodyBytes) return null;
      chunks.push(chunk as Buffer);
    }
  } catch (e) {
    // the connection broke or the client aborted (ECONNRESET, 'aborted'): not an error of the relay
    if (req.destroyed || req.socket.destroyed) throw new ClientAborted();
    throw e;
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * The hash from the body: 32 raw bytes, or JSON `{"hash": "<base64url>"}` with the optional field `"mode"`
 * (only `"solo"` is known; anything else is `bad-mode`). The mode is part of the body, so the signature binds it.
 */
export function hashFrom(
  type: string,
  body: Uint8Array,
):
  | { hash: Uint8Array; solo: boolean; upstream: unknown; hasUpstream: boolean }
  | 'unsupported'
  | 'bad'
  | 'bad-mode' {
  if (type === 'application/octet-stream') {
    return body.length === 32
      ? { hash: body, solo: false, upstream: undefined, hasUpstream: false }
      : 'bad';
  }
  if (type !== JSON_TYPE) return 'unsupported';
  try {
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) as unknown;
    if (typeof data !== 'object' || data === null || Array.isArray(data)) return 'bad';
    const keys = Object.keys(data).sort().join();
    const hash = (data as { hash?: unknown }).hash;
    if (!BODY_KEYS.includes(keys) || typeof hash !== 'string') return 'bad';
    const bytes = fromBase64Url(hash);
    if (!bytes || bytes.length !== 32) return 'bad';
    const hasUpstream = keys.endsWith('upstream');
    const upstream = hasUpstream ? (data as { upstream?: unknown }).upstream : undefined;
    if (!keys.includes('mode')) return { hash: bytes, solo: false, upstream, hasUpstream };
    return (data as { mode?: unknown }).mode === 'solo'
      ? { hash: bytes, solo: true, upstream, hasUpstream }
      : 'bad-mode';
  } catch {
    return 'bad';
  }
}
