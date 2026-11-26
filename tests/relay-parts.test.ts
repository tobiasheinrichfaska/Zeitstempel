import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PARTS } from './relay-source.ts';

// The tests that tie the documents and the counters to "the code of the relay" read the files listed in `PARTS`
// (`tests/relay-source.ts`). A module that the relay is made of and that is not listed would drop its error codes and
// counters out of those tests without a sound. This test holds the list against the imports of `relay/relay.ts`.

/** Modules that relay.ts reaches but that hold no relay rule: limits, data readers, the call out, the tree. */
const NO_RULES = ['limits.ts', 'credentials.ts', 'keys.ts', 'upstream.ts', 'batch.ts'];

const read = (name: string): string =>
  readFileSync(new URL(`../relay/${name}`, import.meta.url), 'utf8');

const importsOf = (name: string): string[] =>
  [...read(name).matchAll(/(?:from|import) '\.\/([\w-]+\.ts)'/g)].map((m) => m[1]!);

const reachable = (from: string): Set<string> => {
  const seen = new Set<string>([from]);
  const todo = [from];
  while (todo.length > 0) {
    for (const next of importsOf(todo.pop()!)) {
      if (!seen.has(next)) {
        seen.add(next);
        todo.push(next);
      }
    }
  }
  return seen;
};

// what the coupling tests look for in the relay's text
const RULE_MARK = /error: '|refused\[|countOnce\(|\bstats\.|\bstats\b/;

describe('the text of the relay rules (`PARTS` of tests/relay-source.ts)', () => {
  it('lists every module that relay/relay.ts reaches, except the ones that hold no rule', () => {
    const missing = [...reachable('relay.ts')].filter(
      (f) => !PARTS.includes(f) && !NO_RULES.includes(f),
    );
    expect(missing).toEqual([]);
  });

  it('lists only files that exist and are reached by relay.ts, once each', () => {
    const files = new Set(readdirSync(new URL('../relay/', import.meta.url)));
    expect(new Set(PARTS).size).toBe(PARTS.length);
    const reached = reachable('relay.ts');
    for (const f of PARTS) {
      expect(files.has(f), f).toBe(true);
      expect(reached.has(f), f).toBe(true);
    }
    for (const f of NO_RULES) expect(files.has(f), f).toBe(true);
  });

  it('the modules left out hold no error code, refusal or counter (else they belong in the list)', () => {
    for (const f of NO_RULES) expect(RULE_MARK.test(read(f)), f).toBe(false);
  });
});
