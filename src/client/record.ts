import { fromBase64Url } from '../lib/bytes.ts';
import { exportEvidenceRecord } from '../lib/ers.ts';
import type { RenewalLink } from '../lib/renewal.ts';
import type { Result } from '../lib/result.ts';
import { readEvidence } from './evidence.ts';

/**
 * Writes evidence (`readEvidence` reads it first: an object or the JSON text) as an RFC 4998 evidence record (DER):
 * the hash, the token and every renewal as one chain (`exportEvidenceRecord`, `docs/client.md`, "ERS-Export"). The
 * record carries no `service`, `receivedAtMs` or repeated facts, so there is no way back to the evidence; read and
 * check it with `readEvidenceRecord` and `verifyEvidenceRecord` of the main entry. Evidence with a collecting relay's
 * `batch` anywhere in it is `export-unsupported`. Never throws.
 */
export async function serializeEvidenceRecord(evidence: unknown): Promise<Result<Uint8Array>> {
  try {
    const read = readEvidence(evidence);
    if (!read.ok) return read;
    const e = read.value;
    const links: RenewalLink[] = [e, ...(e.renewals ?? [])].map((x) => ({
      token: fromBase64Url(x.token)!,
      ...(x.batch === undefined ? {} : { batch: x.batch }),
    }));
    return await exportEvidenceRecord({ hash: fromBase64Url(e.hash)!, links });
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}
