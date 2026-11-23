import http from 'node:http';
import https from 'node:https';
import { RELAY_LIMITS } from './limits.ts';

/** What the relay needs to know about a service to call it. */
export interface UpstreamTarget {
  url: string;
}

export interface UpstreamAnswer {
  status: number;
  contentType: string;
  body: Uint8Array;
}

/** Posts a request to a service. Rejects with an `UpstreamError`; never follows a redirect. */
export type Upstream = (target: UpstreamTarget, body: Uint8Array) => Promise<UpstreamAnswer>;

export class UpstreamError extends Error {
  readonly kind: 'timeout' | 'failed' | 'too-large';
  constructor(kind: 'timeout' | 'failed' | 'too-large') {
    super(kind);
    this.kind = kind;
  }
}

/**
 * The real way out: one POST, TLS certificates checked (Node's defaults), no redirect, a hard
 * deadline and a size cap. The target comes from the allow-list, never from a client.
 */
export const makeNetworkUpstream =
  (timeoutMs: number = RELAY_LIMITS.upstreamTimeoutMs): Upstream =>
  (target, body) =>
    new Promise((resolve, rejectRaw) => {
      // one hard deadline for the whole call (connect to last byte), not an idle timeout
      const timer = setTimeout(() => {
        req.destroy();
        reject(new UpstreamError('timeout'));
      }, timeoutMs);
      const reject = (e: UpstreamError) => {
        clearTimeout(timer);
        rejectRaw(e);
      };
      const url = new URL(target.url);
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(
        url,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/timestamp-query',
            Accept: 'application/timestamp-reply',
            'Content-Length': String(body.length),
            'User-Agent': 'zeitstempel-relay',
          },
          agent: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > RELAY_LIMITS.upstreamBytes) {
              req.destroy();
              reject(new UpstreamError('too-large'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            clearTimeout(timer);
            resolve({
              status: res.statusCode ?? 0,
              contentType: String(res.headers['content-type'] ?? '')
                .split(';')[0]!
                .trim()
                .toLowerCase(),
              body: new Uint8Array(Buffer.concat(chunks)),
            });
          });
          res.on('error', () => reject(new UpstreamError('failed')));
        },
      );
      req.on('error', () => reject(new UpstreamError('failed')));
      req.end(body);
    });

export const networkUpstream: Upstream = makeNetworkUpstream();
