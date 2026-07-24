import { AtomicStore } from '../core.ts';

export class ReplayStore {
  private readonly store: AtomicStore<{ entries: Record<string, number> }>;
  constructor(path: string, private readonly retentionMs: number) { this.store = new AtomicStore(path, { entries: {} }); }
  accept(nonce: string, now = Date.now()): boolean {
    let accepted = false;
    this.store.update((current) => {
      const entries = Object.fromEntries(Object.entries(current.entries).filter(([, value]) => now - value <= this.retentionMs));
      if (entries[nonce] === undefined) { entries[nonce] = now; accepted = true; }
      return { entries };
    });
    return accepted;
  }
}
