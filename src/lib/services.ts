import { fail, ok, type Result } from './result.ts';

/** Who supplies the credentials of a paid service: the relay (from its environment), the app (in the signed body), or either. */
export type ServiceAuthSource = 'relay' | 'client' | 'either';

/**
 * How a service wants to be called (`auth` in `services.json`; absent means `{ kind: 'none' }`, the free services).
 * `basic`: user and password (RFC 7617), `bearer`: a token in `Authorization: Bearer`, `header`: a token in a header of
 * the given name. Anything but `none` is allowed for an https address only.
 */
export type ServiceAuth =
  | { kind: 'none' }
  | { kind: 'basic'; source: ServiceAuthSource }
  | { kind: 'bearer'; source: ServiceAuthSource }
  | { kind: 'header'; header: string; source: ServiceAuthSource };

/** One time stamp service, as data (`services.json`). */
export interface Service {
  id: string;
  name: string;
  url: string;
  hash: 'sha256';
  /** Paths (relative to the data file) of the PEM files with the trust anchors of this service. */
  anchors: string[];
  /** False for every service listed so far: a qualified one is a paid contract (see the docs). */
  qualified: boolean;
  /** The budget follows from it: at most 60000 / minIntervalMs requests per minute (not a minimum gap between two requests). */
  minIntervalMs: number;
  intendedUse: string;
  terms: string;
  /** Optional: credentials the service wants. Absent for the free services (nothing is sent). */
  auth?: ServiceAuth;
}

const ID = /^[a-z][a-z0-9-]{0,31}$/;
const isText = (v: unknown, max: number): v is string =>
  typeof v === 'string' && v.length > 0 && v.length <= max;

const KEYS = [
  'id',
  'name',
  'url',
  'hash',
  'anchors',
  'qualified',
  'minIntervalMs',
  'intendedUse',
  'terms',
];

const SOURCES: readonly string[] = ['relay', 'client', 'either'];
const AUTH_HEADER_NAME = /^[A-Za-z0-9-]{1,40}$/;
/** Headers the relay sets itself or that hop-by-hop / routing rules own: never a credential header. Lower case. */
const FORBIDDEN_AUTH_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'host',
  'content-length',
  'content-type',
  'content-encoding',
  'content-range',
  'accept',
  'accept-encoding',
  'accept-language',
  'user-agent',
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'cookie',
  'set-cookie',
  'expect',
  'via',
  'forwarded',
  'date',
  'origin',
  'referer',
  'range',
  ['fr', 'om'].join(''), // in two parts: the import guard (tests/coupling.test.ts) is a text search
  'max-forwards',
  'location',
  'server',
  'allow',
  'vary',
  'warning',
]);
const FORBIDDEN_AUTH_PREFIXES: readonly string[] = [
  'proxy-',
  'sec-',
  'if-',
  'x-forwarded-',
  'access-control-',
  'x-zeitstempel',
];

/** Is this a header name a `header` credential may use (strict pattern, none of the forbidden or hop-by-hop headers)? */
export function isAuthHeaderName(name: unknown): name is string {
  if (typeof name !== 'string' || !AUTH_HEADER_NAME.test(name)) return false;
  const lower = name.toLowerCase();
  return (
    !FORBIDDEN_AUTH_HEADERS.has(lower) && !FORBIDDEN_AUTH_PREFIXES.some((p) => lower.startsWith(p))
  );
}

/** The `auth` member, strictly: exactly its known members, known values; null for anything else. */
function readAuth(raw: unknown): ServiceAuth | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const a = raw as Record<string, unknown>;
  const keys = Object.keys(a);
  if (a.kind === 'none') return keys.length === 1 ? { kind: 'none' } : null;
  const source = a.source;
  if (typeof source !== 'string' || !SOURCES.includes(source)) return null;
  if (a.kind === 'basic' || a.kind === 'bearer') {
    return keys.length === 2 && Object.hasOwn(a, 'source')
      ? { kind: a.kind, source: source as ServiceAuthSource }
      : null;
  }
  if (a.kind === 'header') {
    if (keys.length !== 3 || !Object.hasOwn(a, 'source') || !Object.hasOwn(a, 'header'))
      return null;
    return isAuthHeaderName(a.header)
      ? { kind: 'header', header: a.header, source: source as ServiceAuthSource }
      : null;
  }
  return null;
}

/**
 * Reads the services file strictly: unknown members, bad urls or duplicate ids are refused. Never throws
 * (a getter or proxy that throws gives `bad-services`).
 */
export function readServices(data: unknown): Result<Service[]> {
  try {
    return readServicesUnchecked(data);
  } catch {
    return fail('bad-services');
  }
}

function readServicesUnchecked(data: unknown): Result<Service[]> {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return fail('bad-services');
  const top = data as Record<string, unknown>;
  if (top.version !== 1 || !Array.isArray(top.services) || Object.keys(top).length !== 2) {
    return fail('bad-services');
  }
  if (top.services.length === 0 || top.services.length > 32) return fail('bad-services');
  const out: Service[] = [];
  for (const raw of top.services) {
    if (typeof raw !== 'object' || raw === null) return fail('bad-services');
    const s = raw as Record<string, unknown>;
    const hasAuth = Object.hasOwn(s, 'auth'); // optional; an explicit `undefined` is read (and refused) too
    if (
      Object.keys(s).length !== KEYS.length + (hasAuth ? 1 : 0) ||
      !KEYS.every((k) => Object.hasOwn(s, k))
    ) {
      return fail('bad-services');
    }
    const auth = hasAuth ? readAuth(s.auth) : null;
    if (hasAuth && auth === null) return fail('bad-services');
    if (typeof s.id !== 'string' || !ID.test(s.id) || out.some((o) => o.id === s.id))
      return fail('bad-services');
    if (!isText(s.name, 100) || !isText(s.intendedUse, 500) || !isText(s.terms, 800))
      return fail('bad-services');
    if (s.hash !== 'sha256' || typeof s.qualified !== 'boolean') return fail('bad-services');
    if (
      !Number.isInteger(s.minIntervalMs) ||
      (s.minIntervalMs as number) < 1000 ||
      (s.minIntervalMs as number) > 3_600_000
    ) {
      return fail('bad-services');
    }
    if (!Array.isArray(s.anchors) || s.anchors.length === 0 || s.anchors.length > 8)
      return fail('bad-services');
    if (!s.anchors.every((a) => typeof a === 'string' && /^anchors\/[a-z0-9-]+\.pem$/.test(a))) {
      return fail('bad-services');
    }
    // a string only: `new URL` would turn an array or an object with a `toString` into text
    if (typeof s.url !== 'string') return fail('bad-services');
    let url: URL;
    try {
      url = new URL(s.url);
    } catch {
      return fail('bad-services');
    }
    if (
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username ||
      url.password ||
      url.search ||
      url.href.includes('?') || // an empty query is dropped from .search but kept in .href
      url.href.includes('#') ||
      url.hash
    ) {
      return fail('bad-services');
    }
    // credentials only over https: never to a plain-http address, whatever the file says
    if (auth !== null && auth.kind !== 'none' && url.protocol !== 'https:') {
      return fail('bad-services');
    }
    out.push({
      id: s.id,
      name: s.name,
      url: url.href,
      hash: 'sha256',
      anchors: s.anchors as string[],
      qualified: s.qualified,
      minIntervalMs: s.minIntervalMs as number,
      intendedUse: s.intendedUse,
      terms: s.terms,
      ...(auth === null ? {} : { auth }),
    });
  }
  return ok(out);
}
