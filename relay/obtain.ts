import {
  buildTimestampRequest,
  readTimestampResponse,
  toBase64Url,
  verifyTimestampToken,
  type VerifiedTimestamp,
} from '../src/index.ts';
import { RELAY_LIMITS } from './limits.ts';
import type { RelayContext, RelayService } from './types.ts';
import { UpstreamError } from './upstream.ts';
import type { UpstreamCredentials } from './credentials.ts';

export type Obtained =
  | { ok: true; token: Uint8Array; verified: VerifiedTimestamp }
  | {
      ok: false;
      status: number;
      body: { error: string; reason?: string };
      headers?: Record<string, string>;
      /** Nothing was sent to the service for this request (busy, shutting down, key lapsed): what it spent comes back. */
      unsent?: true;
    };

/** One stamp from a service (`obtain`), and what the relay notes about the calls (numbers per offered service only). */
export function createObtain(ctx: RelayContext) {
  const { options, mono, countOnce } = ctx;
  /** What a stamp obtained from a service tells the caller (the fields of the 200 answer, without `batch`). */
  function stampBody(service: RelayService, got: Obtained & { ok: true }) {
    return {
      service: service.id,
      genTime: got.verified.genTime,
      accuracyMs: got.verified.accuracyMs,
      serial: got.verified.serial,
      token: toBase64Url(got.token),
    };
  }

  /**
   * One stamp from a service for `hash`: builds the request with a nonce of the relay, calls the one address of
   * the service, reads and checks the answer (hash, nonce, signature, chain, and a time around the moment of
   * the request). The same for a single request and for the imprint of a batch.
   */
  async function obtain(
    service: RelayService,
    hash: Uint8Array,
    creds?: UpstreamCredentials,
  ): Promise<Obtained> {
    const nonce = options.random(8);
    const request = buildTimestampRequest(hash, nonce);
    if (!request.ok) return { ok: false, status: 500, body: { error: 'internal' } };
    const sentMs = options.now(); // the moment the request goes to the service: the token must not be older
    serviceCalledAt.set(service.id, mono()); // service ids of `byId` only: the table cannot grow
    let answer;
    try {
      answer =
        creds === undefined
          ? await options.upstream(service, request.value)
          : await options.upstream(service, request.value, creds);
    } catch (e) {
      const kind = e instanceof UpstreamError ? e.kind : 'failed';
      return {
        ok: false,
        status: kind === 'timeout' ? 504 : 502,
        body: { error: `upstream-${kind}` },
      };
    }
    if (answer.status !== 200 || answer.contentType !== 'application/timestamp-reply') {
      return { ok: false, status: 502, body: { error: 'upstream-refused' } };
    }
    const response = readTimestampResponse(answer.body);
    if (!response.ok) {
      return {
        ok: false,
        status: 502,
        body: { error: 'upstream-invalid', reason: response.reason },
      };
    }
    // The time of the token must lie around the moment of the request: not ahead of the relay's clock and not
    // older than the request (both within `genTimeSlackMs`). Without the lower bound a service key that has
    // expired or leaked could hand out back-dated tokens that still verify.
    const answeredMs = options.now(); // the relay's clock when the answer is read (also the `now` of the check)
    const verified = await verifyTimestampToken(response.value.token, hash, service.anchorPems, {
      expectedNonce: nonce,
      now: new Date(answeredMs),
      maxSkewMs: RELAY_LIMITS.genTimeSlackMs,
      minGenTime: new Date(sentMs - RELAY_LIMITS.genTimeSlackMs),
    });
    if (!verified.ok) {
      // a cause of its own in the counters (a service that back-dates is an alarm, not a client error)
      if (verified.reason === 'time-too-old') countOnce('upstream-too-old');
      return {
        ok: false,
        status: 502,
        body: { error: 'upstream-invalid', reason: verified.reason },
      };
    }
    const genMs = Date.parse(verified.value.genTime);
    if (Number.isFinite(genMs)) lastGenDelta.set(service.id, Math.abs(genMs - answeredMs));
    return { ok: true, token: response.value.token, verified: verified.value };
  }

  /** Per service id (offered services only): the monotonic time of the last call made, and the last `genTime` difference. */
  const serviceCalledAt = new Map<string, number>();
  const lastGenDelta = new Map<string, number>();

  return { obtain, stampBody, serviceCalledAt, lastGenDelta };
}
