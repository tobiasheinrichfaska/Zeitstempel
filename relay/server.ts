import http from 'node:http';
import { createRelay, type Relay, type RelayOptions } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';

/** How long a socket may stay open after the relay wrote its last word to it. */
const CLOSE_GRACE_MS = 1_000;

/** Addresses that only a process on the same machine can reach; the one list for the settings and the server. */
export const LOOPBACK_HOSTS: readonly string[] = ['127.0.0.1', '::1', 'localhost'];

/**
 * The idle time between two requests: `override` (RELAY_KEEPALIVE_MS) when given, else the long one for a
 * loopback binding (a proxy on the same machine) and the short one for any other binding or none
 * (anyone may connect: idle connections must not hold the places for long).
 */
export function keepAliveFor(host: string | undefined, override?: number): number {
  if (override !== undefined) return override;
  return host !== undefined && LOOPBACK_HOSTS.includes(host)
    ? RELAY_LIMITS.keepAliveProxyMs
    : RELAY_LIMITS.keepAliveDirectMs;
}

/** The HTTP server around a relay: short request deadlines, a keep-alive that depends on the binding, nothing logged. */
export function createRelayServer(
  options: RelayOptions,
  /** For tests: smaller limits to see the behaviour quickly. */
  limits: {
    maxConnections?: number;
    requestTimeoutMs?: number;
    /** The address the server will listen on (the keep-alive depends on it); none means all interfaces. */
    host?: string;
    /** RELAY_KEEPALIVE_MS: replaces the keep-alive of both bindings. */
    keepAliveMs?: number;
  } = {},
): { server: http.Server; relay: Relay } {
  const relay = createRelay(options);
  // connectionsCheckingInterval: how often the server looks for connections past their deadline
  const server = http.createServer({ connectionsCheckingInterval: 1_000 }, relay.handle);
  const timeout = limits.requestTimeoutMs ?? RELAY_LIMITS.requestTimeoutMs;
  // Node's own answers to a broken or slow client (408, 431, 400), now with the 408 counted apart from
  // a client that went away. Nothing of the request is looked at or logged.
  server.on('clientError', (err: NodeJS.ErrnoException, socket) => {
    if (socket.destroyed || !socket.writable) return void socket.destroy();
    let status = '400 Bad Request';
    if (err.code === 'ERR_HTTP_REQUEST_TIMEOUT') {
      relay.requestTimedOut(socket);
      status = '408 Request Timeout';
    } else if (err.code === 'HPE_HEADER_OVERFLOW') {
      status = '431 Request Header Fields Too Large';
    }
    // end() only finishes once the client has read what was queued before; a client that never reads
    // (pipelined requests it ignores) would keep the socket open for good. So the socket is destroyed at
    // the latest after a second, whatever the client does.
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
    setTimeout(() => socket.destroy(), CLOSE_GRACE_MS).unref();
  });
  server.requestTimeout = timeout;
  server.headersTimeout = timeout;
  server.keepAliveTimeout = keepAliveFor(limits.host, limits.keepAliveMs);
  server.maxHeadersCount = 50;
  server.maxConnections = limits.maxConnections ?? RELAY_LIMITS.maxConnections;
  return { server, relay };
}
