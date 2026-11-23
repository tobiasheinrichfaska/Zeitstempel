import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const FIXTURES = new URL('./fixtures/', import.meta.url);

export const fixture = (name: string): Uint8Array =>
  new Uint8Array(readFileSync(new URL(name, FIXTURES)));
export const fixtureText = (name: string): string => readFileSync(new URL(name, FIXTURES), 'utf8');

export const sha256 = (text: string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(text).digest());

/** The nonce used for the recorded FreeTSA request (`tests/fixtures/freetsa.tsq`). */
export const FREETSA_NONCE = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
