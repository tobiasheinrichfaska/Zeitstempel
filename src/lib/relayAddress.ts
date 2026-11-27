/**
 * Addresses of a relay, as an app lists them in its build (comma-separated). Pure, nothing throws.
 * Rules: an https address, or an http address for the own machine (`localhost`, `127.0.0.1`), no
 * credentials, one plain line without white space.
 */

/** Longest address in characters. */
export const MAX_RELAY_ADDRESS_CHARS = 200;

/** Plain text: no control characters, no lone surrogates, no noncharacters (written with char codes). */
function plainText(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0xfffe || c === 0xffff) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** An empty address (off), or an https address (http only for the own machine), one plain line. */
export function isRelayAddress(value: unknown): value is string {
  if (value === '') return true;
  if (
    typeof value !== 'string' ||
    value.length > MAX_RELAY_ADDRESS_CHARS ||
    !plainText(value) ||
    /\s/.test(value)
  ) {
    return false;
  }
  try {
    const url = new URL(value);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    return (
      (url.protocol === 'https:' || (url.protocol === 'http:' && local)) &&
      url.username === '' &&
      url.password === ''
    );
  } catch {
    return false;
  }
}

/**
 * The addresses a build allows (text such as the value of a build variable, separated by commas): trimmed,
 * only valid addresses, each once; `undefined` or an empty text gives an empty list.
 */
export function parseRelayList(raw: string | undefined): string[] {
  const list = (raw ?? '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '' && isRelayAddress(part));
  return [...new Set(list)];
}

/** The origin of an address (what a page's policy has to allow), or `null` if it is not an address. */
export function relayOrigin(address: string): string | null {
  try {
    return new URL(address).origin;
  } catch {
    return null;
  }
}

/** Whether a saved setting may be used: not empty and exactly one of the allowed addresses. */
export const relayUsable = (setting: string, allowed: readonly string[]): boolean =>
  setting !== '' && allowed.includes(setting);
