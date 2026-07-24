import { createHash, verify } from 'node:crypto';
import { canonicalize } from './canonical.js';
export function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
export function verifyProof(publicKey, proof, result) { const { signature, ...unsigned } = proof; if (proof.version !== '1' || proof.resultSha256 !== sha256(canonicalize(result))) return false; return verify(null, Buffer.from(canonicalize(unsigned)), publicKey, Buffer.from(signature, 'base64')); }
