import http from 'node:http';
import { createRelay, type Relay, type RelayOptions } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';

/** The HTTP server around a relay: short deadlines, no keep-alive surprises, nothing logged. */
export function createRelayServer(options: RelayOptions): { server: http.Server; relay: Relay } {
  const relay = createRelay(options);
  const server = http.createServer(relay.handle);
  server.requestTimeout = RELAY_LIMITS.requestTimeoutMs;
  server.headersTimeout = RELAY_LIMITS.requestTimeoutMs;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return { server, relay };
}
