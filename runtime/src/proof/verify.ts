import { verifyCanonical, type BabyXProof } from '../core.ts';

export function verifyProof(publicKey: string | Buffer, proof: BabyXProof): boolean {
  const { signature, ...unsigned } = proof;
  return verifyCanonical(publicKey, unsigned, signature);
}
