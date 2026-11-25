import { createHash } from 'node:crypto';
import { isAuthHeaderName, type ServiceAuth } from '../src/lib/services.ts';
import { RELAY_LIMITS } from './limits.ts';

/**
 * Credentials for one paid service, as the relay holds them in memory only: never logged, never counted, never in an
 * error text. The header name of `header` always comes from `services.json` (never from a client).
 */
export type UpstreamCredentials =
  | { kind: 'basic'; user: string; password: string }
  | { kind: 'bearer'; token: string }
  | { kind: 'header'; header: string; token: string };

// Printable ASCII only: no control characters, no CR, no LF, nothing above 0x7E (header injection). A password may
// hold a space, quote and backslash; a user name may not hold a colon (RFC 7617); a token holds no space, no quote and
// no backslash (so the signed JSON body stays within `bodyBytes`, see tests/upstream-auth.test.ts).
const USER = new RegExp(`^[\\x20-\\x39\\x3B-\\x7E]{1,${RELAY_LIMITS.upstreamUserMax}}$`);
const PASSWORD = new RegExp(`^[\\x20-\\x7E]{1,${RELAY_LIMITS.upstreamPasswordMax}}$`);
const TOKEN = new RegExp(`^[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,${RELAY_LIMITS.upstreamTokenMax}}$`);

const isUser = (v: unknown): v is string => typeof v === 'string' && USER.test(v);
const isPassword = (v: unknown): v is string => typeof v === 'string' && PASSWORD.test(v);
const isToken = (v: unknown): v is string => typeof v === 'string' && TOKEN.test(v);

/** Are these credentials well formed (every field checked again, also where they come from the relay's own settings)? */
export function validCredentials(c: UpstreamCredentials): boolean {
  switch (c.kind) {
    case 'basic':
      return isUser(c.user) && isPassword(c.password);
    case 'bearer':
      return isToken(c.token);
    case 'header':
      return isAuthHeaderName(c.header) && isToken(c.token);
    default:
      return false;
  }
}

/**
 * The `upstream` member of a request body for a service that wants `auth`: exactly the members of its kind, strings of
 * the allowed characters and lengths. Null for anything else (the relay answers `400 bad-upstream`).
 */
export function credentialsFromClient(
  auth: ServiceAuth,
  value: unknown,
): UpstreamCredentials | null {
  if (auth.kind === 'none') return null;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  if (Object.getPrototypeOf(value) !== Object.prototype) return null; // JSON.parse gives plain objects
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v).sort().join();
  if (auth.kind === 'basic') {
    if (keys !== 'password,user' || !isUser(v.user) || !isPassword(v.password)) return null;
    return { kind: 'basic', user: v.user, password: v.password };
  }
  if (keys !== 'token' || !isToken(v.token)) return null;
  return auth.kind === 'bearer'
    ? { kind: 'bearer', token: v.token }
    : { kind: 'header', header: auth.header, token: v.token };
}

/**
 * The credentials the relay holds itself (the value of its environment variable): `user:password` for `basic` (the
 * first colon separates, a password may hold more), the token otherwise. Null when the value is not well formed.
 */
export function credentialsFromText(auth: ServiceAuth, text: string): UpstreamCredentials | null {
  if (auth.kind === 'none') return null;
  if (auth.kind === 'basic') {
    const at = text.indexOf(':');
    if (at < 0) return null;
    const user = text.slice(0, at);
    const password = text.slice(at + 1);
    return isUser(user) && isPassword(password) ? { kind: 'basic', user, password } : null;
  }
  if (!isToken(text)) return null;
  return auth.kind === 'bearer'
    ? { kind: 'bearer', token: text }
    : { kind: 'header', header: auth.header, token: text };
}

/**
 * Who the credentials belong to, for the planner and the counters: a SHA-256 digest (hex) over kind and fields, each
 * with its length, so no two different credentials meet. Lives in memory only and is never output, logged or counted.
 */
export function credentialIdentity(c: UpstreamCredentials): string {
  const parts = c.kind === 'basic' ? [c.kind, c.user, c.password] : [c.kind, c.token];
  const h = createHash('sha256');
  for (const p of parts) h.update(`${p.length}:${p}\n`);
  return h.digest('hex');
}

/** The one request header the credentials need. Throws for malformed credentials (never reached by checked input). */
export function credentialHeader(c: UpstreamCredentials): [name: string, value: string] {
  if (!validCredentials(c)) throw new Error('bad credentials'); // no content
  switch (c.kind) {
    case 'basic':
      return [
        'Authorization',
        `Basic ${Buffer.from(`${c.user}:${c.password}`, 'latin1').toString('base64')}`,
      ];
    case 'bearer':
      return ['Authorization', `Bearer ${c.token}`];
    default:
      return [c.header, c.token];
  }
}
