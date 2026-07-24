export interface Candidate { id: string; sourceIdentity: Record<string, unknown>; state: 'submitted' | 'building' | 'ready' | 'refuted' | 'bounded-pass'; }
