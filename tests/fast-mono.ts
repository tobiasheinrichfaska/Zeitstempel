/**
 * A monotonic clock that runs a minute ahead at every reading, for the tests of everything but the minimum distance of
 * single operation (`tests/single-spacing.test.ts`): such a test sends several stamps one after the other to a service
 * of 5 s or 15 s and would otherwise wait for the distance each time. Every wait of the relay is then already over.
 */
export const fastMonotonic = (): (() => number) => {
  let t = 0;
  return () => (t += 60_000);
};
