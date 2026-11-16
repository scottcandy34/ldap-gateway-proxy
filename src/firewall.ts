import { canonicalFilter } from "./filter.js";
import type { BindRule, ScopeName } from "./types.js";

export type Query = { base: string; scope: ScopeName; filter: string };

export function normalizeDn(dn: string): string {
  return dn.trim().replace(/\s*,\s*/g, ",").replace(/\s*=\s*/g, "=").toLowerCase();
}

export function queryKey(bindDn: string, query: Query): string {
  return `${normalizeDn(bindDn)}\n${normalizeDn(query.base)}\n${query.scope}\n${query.filter}`;
}

export class BindMap {
  private readonly rules = new Map<string, BindRule>();

  constructor(rules: BindRule[]) {
    for (const rule of rules) this.rules.set(normalizeDn(rule.dn), rule);
  }

  lookup(dn: string): BindRule | undefined {
    return this.rules.get(normalizeDn(dn));
  }

  allows(dn: string, query: Query, allowAllBinds: boolean): boolean {
    const rule = this.lookup(dn);
    if (!rule) return allowAllBinds;
    if (!rule.allowedQueries) return true;
    return rule.allowedQueries.some((allowed) =>
      normalizeDn(allowed.base) === normalizeDn(query.base) &&
      allowed.scope === query.scope &&
      allowed.filter === query.filter,
    );
  }
}

export function compileQuery(base: string, scope: ScopeName, filter: string): Query {
  return { base, scope, filter: canonicalFilter(filter) };
}
