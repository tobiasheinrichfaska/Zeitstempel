import http from 'node:http';
import { createRelay, type Relay, type RelayOptions } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';

/** The HTTP server around a relay: short deadlines, no keep-alive surprises, nothing logged. */
export function createRelayServer(
  options: RelayOptions,
  /** For tests: smaller limits to see the behaviour quickly. */
  limits: { maxConnections?: number; requestTimeoutMs?: number } = {},
): { server: http.Server; relay: Relay } {
  const relay = createRelay(options);
  // connectionsCheckingInterval: how often the server looks for connections past their deadline
  const server = http.createServer({ connectionsCheckingInterval: 1_000 }, relay.handle);
  const timeout = limits.requestTimeoutMs ?? RELAY_LIMITS.requestTimeoutMs;
  server.requestTimeout = timeout;
  server.headersTimeout = timeout;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.maxConnections = limits.maxConnections ?? RELAY_LIMITS.maxConnections;
  return { server, relay };
}
