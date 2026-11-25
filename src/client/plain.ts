/**
 * Reading of hostile input for the client: a plain object is read through the property descriptors, once per
 * field, into a fresh object (no prototype). A getter, a Proxy whose traps throw or answer differently, a class
 * instance, an array or an unknown field gives `null`: the caller turns that into its own error code.
 */
export function plainFields(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> | null {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const keys = Object.keys(value);
    if (keys.length > allowed.length) return null;
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (!allowed.includes(key)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !('value' in descriptor)) return null; // a getter is no data
      out[key] = descriptor.value;
    }
    for (const key of required) if (!(key in out)) return null;
    return out;
  } catch {
    return null;
  }
}

/**
 * The elements of a list, by length and index (never through the iterator), at most `max`; `null` for anything
 * that is no list or that throws.
 */
export function listItems(value: unknown, max: number): unknown[] | null {
  try {
    if (!Array.isArray(value)) return null;
    const count: unknown = (value as unknown[]).length;
    if (typeof count !== 'number' || !Number.isInteger(count) || count < 0 || count > max) {
      return null;
    }
    const out: unknown[] = [];
    for (let i = 0; i < count; i += 1) out.push((value as unknown[])[i]);
    return out;
  } catch {
    return null;
  }
}
