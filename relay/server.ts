import http from 'node:http';
import { createRelay, type Relay, type RelayOptions } from './relay.ts';
import { RELAY_LIMITS } from './limits.ts';

/** How long a socket may stay open after the relay wrote its last word to it. */
const CLOSE_GRACE_MS = 1_000;

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
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.maxConnections = limits.maxConnections ?? RELAY_LIMITS.maxConnections;
  return { server, relay };
}
