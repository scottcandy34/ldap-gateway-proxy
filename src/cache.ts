export type CacheEntry = { ops: Buffer[]; bytes: number; expires: number };

export class SearchCache {
  private readonly entries = new Map<string, CacheEntry>();
  private used = 0;

  constructor(
    private readonly maxBytes: number,
    private readonly ttlMs: number,
  ) {}

  get(key: string, now = Date.now()): Buffer[] | undefined {
    const entry = this.entries.get(key);
    if (!entry) return;
    if (entry.expires <= now) {
      this.delete(key);
      return;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.ops;
  }

  set(key: string, ops: Buffer[], now = Date.now()): void {
    if (this.maxBytes <= 0 || this.ttlMs <= 0) return;
    const bytes = ops.reduce((sum, op) => sum + op.length, 0);
    if (bytes > this.maxBytes) return;
    this.delete(key);
    while (this.used + bytes > this.maxBytes && this.entries.size > 0) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.delete(oldest);
    }
    this.entries.set(key, { ops, bytes, expires: now + this.ttlMs });
    this.used += bytes;
  }

  private delete(key: string): void {
    const entry = this.entries.get(key);
    if (!entry) return;
    this.used -= entry.bytes;
    this.entries.delete(key);
  }
}
