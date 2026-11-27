import { describe, expect, it } from 'vitest';
import {
  MAX_RELAY_ADDRESS_CHARS,
  isRelayAddress,
  parseRelayList,
  relayOrigin,
  relayUsable,
} from '../src/lib/index.ts';

const RELAY = 'https://relay.example';

describe('relay addresses', () => {
  it('accepts off, https and http for the own machine', () => {
    expect(isRelayAddress('')).toBe(true);
    expect(isRelayAddress('https://relay.example/stamp')).toBe(true);
    expect(isRelayAddress('http://localhost:8787/x')).toBe(true);
    expect(isRelayAddress('http://127.0.0.1/x')).toBe(true);
  });

  it('refuses everything else, without throwing', () => {
    const bad: unknown[] = [
      'http://relay.example/x',
      'ftp://relay.example',
      'https://user@relay.example',
      'https://:secret@relay.example',
      'https://relay.example/a b',
      'https://relay.example/\n',
      'not an address',
      'https://' + 'a'.repeat(MAX_RELAY_ADDRESS_CHARS),
      'https://relay.example/\u0000',
      'https://relay.example/\ud800',
      7,
      null,
      undefined,
    ];
    for (const value of bad) expect(isRelayAddress(value), String(value)).toBe(false);
  });

  it('reads the list of a build: trimmed, valid, once each', () => {
    expect(parseRelayList(undefined)).toEqual([]);
    expect(parseRelayList('')).toEqual([]);
    expect(
      parseRelayList(' https://a.example/x , ftp://no , https://a.example/x,http://localhost:1/y '),
    ).toEqual(['https://a.example/x', 'http://localhost:1/y']);
  });

  it('knows the origin and which setting a build may use', () => {
    expect(relayOrigin('https://relay.example/stamp?x=1')).toBe('https://relay.example');
    expect(relayOrigin('http://localhost:8787/x')).toBe('http://localhost:8787');
    expect(relayOrigin('nonsense')).toBeNull();
    expect(relayUsable(RELAY, [RELAY])).toBe(true);
    expect(relayUsable(RELAY, [])).toBe(false); // a typed-in address not named by the build is not used
    expect(relayUsable(RELAY, ['https://other.example/x'])).toBe(false);
    expect(relayUsable('', [RELAY])).toBe(false); // off
  });
});
