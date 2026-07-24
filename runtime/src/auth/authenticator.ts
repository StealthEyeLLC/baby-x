import { verifyCanonical, type JsonObject } from '../core.ts';

export interface OwnerEnvelope extends JsonObject {
  subject: 'stealtheye-owner';
  authorityClass: 'unrestricted-owner';
  timestamp: string;
  nonce: string;
  signature: string;
}

export function authenticateOwner(publicKey: string | Buffer, envelope: OwnerEnvelope, maximumAgeMs: number): void {
  if (envelope.subject !== 'stealtheye-owner' || envelope.authorityClass !== 'unrestricted-owner') throw new Error('owner identity mismatch');
  const age = Math.abs(Date.now() - Date.parse(envelope.timestamp));
  if (!Number.isFinite(age) || age > maximumAgeMs) throw new Error('request timestamp outside freshness window');
  const { signature, ...unsigned } = envelope;
  if (!verifyCanonical(publicKey, unsigned, signature)) throw new Error('signature verification failed');
}
