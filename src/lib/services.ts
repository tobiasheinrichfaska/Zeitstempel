import { fail, ok, type Result } from './result.ts';

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
  /** Smallest wait between two requests to this service. */
  minIntervalMs: number;
  intendedUse: string;
  terms: string;
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

/** Reads the services file strictly: unknown members, bad urls or duplicate ids are refused. */
export function readServices(data: unknown): Result<Service[]> {
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
    if (Object.keys(s).length !== KEYS.length || !KEYS.every((k) => Object.hasOwn(s, k))) {
      return fail('bad-services');
    }
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
    let url: URL;
    try {
      url = new URL(s.url as string);
    } catch {
      return fail('bad-services');
    }
    if (
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
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
    });
  }
  return ok(out);
}
