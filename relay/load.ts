import { readFileSync } from 'node:fs';
import { readServices } from '../src/index.ts';
import type { RelayService } from './relay.ts';

const ROOT = new URL('../', import.meta.url);

/** Reads `services.json` and the PEM files it names. Throws with a message a person can read. */
export function loadServices(file = 'services.json', root: URL = ROOT): RelayService[] {
  const parsed = readServices(JSON.parse(readFileSync(new URL(file, root), 'utf8')) as unknown);
  if (!parsed.ok) throw new Error(`${file}: keine gültige Dienstliste (${parsed.reason})`);
  return parsed.value.map((s) => ({
    ...s,
    anchorPems: s.anchors.map((a) => readFileSync(new URL(a, root), 'utf8')),
  }));
}
