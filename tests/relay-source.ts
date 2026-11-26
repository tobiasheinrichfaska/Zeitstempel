import { readFileSync } from 'node:fs';

/**
 * The text of the relay rules. They live in `relay/relay.ts` (the wiring and the request) and the parts it is made of; the tests
 * that tie the documents and the counters to "the code of the relay" read all of them, as they read the one file before the split.
 */
const PARTS = [
  'relay.ts',
  'types.ts',
  'body.ts',
  'auth-head.ts',
  'budgets.ts',
  'identities.ts',
  'obtain.ts',
  'planner.ts',
  'flush.ts',
];

export const relaySource = (): string =>
  PARTS.map((name) => readFileSync(new URL(`../relay/${name}`, import.meta.url), 'utf8')).join(
    '\n',
  );
