import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export function base64url(buffer) { return Buffer.from(buffer).toString('base64url'); }
export function pkceChallenge(verifier) { return base64url(createHash('sha256').update(verifier).digest()); }
export function verifyPkce(verifier, expected) { const actual = Buffer.from(pkceChallenge(verifier)); const wanted = Buffer.from(expected); return actual.length === wanted.length && timingSafeEqual(actual, wanted); }
export function opaqueToken(bytes = 32) { return randomBytes(bytes).toString('base64url'); }
