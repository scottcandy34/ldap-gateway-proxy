import { isIP } from "node:net";
import { formatAddress, looksLikeAddress, parseAddress } from "./address.js";
import type { Address, BackendMode, Config, Route, ServerDef, Strategy } from "./types.js";

export type Captures = { sni: string; groups: string[] };

export type Target = Address & { key: string };

export type Match = {
  route: Route;
  captures: Captures;
  targets: Target[];
  reason: string;
  backendMode: BackendMode | "inherit";
};

type Compiled = { route: Route; matchers: Array<{ source: string; regex: RegExp }> };

export class Router {
  private readonly compiled: Compiled[];
  private readonly servers: Map<string, ServerDef>;
  private readonly rr = new Map<Route, number>();
  private readonly active = new Map<string, number>();

  constructor(private readonly config: Config) {
    this.servers = new Map(config.servers.map((server) => [server.name, server]));
    this.compiled = config.routes.map((route) => ({
      route,
      matchers: route.hosts.map((host) => ({ source: host, regex: compileHost(host) })),
    }));
  }

  normalize(raw: string | undefined): string {
    if (!raw) return "";
    let host = raw.trim().toLowerCase();
    if (host.endsWith(".")) host = host.slice(0, -1);
    return host;
  }

  isIp(host: string): boolean {
    if (!host) return false;
    const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
    return isIP(bare) !== 0;
  }

  match(raw: string | undefined): Match | null {
    const sni = this.normalize(raw);
    if (!sni) return null;
    for (const entry of this.compiled) {
      for (const matcher of entry.matchers) {
        const found = matcher.regex.exec(sni);
        if (!found) continue;
        const captures: Captures = { sni, groups: found.slice(1) };
        return {
          route: entry.route,
          captures,
          targets: this.targetsFor(entry.route, captures),
          reason: matcher.source,
          backendMode: this.modeFor(entry.route),
        };
      }
    }
    if (this.config.unmatched === "reject") return null;
    return this.unmatched(sni);
  }

  order(match: Match): Target[] {
    const targets = match.targets;
    if (targets.length <= 1) return targets;
    const strategy = match.route.strategy;
    if (strategy === "first") return targets;
    if (strategy === "random") return shuffle(targets);
    if (strategy === "least-connections") {
      return [...targets].sort((a, b) => (this.active.get(a.key) ?? 0) - (this.active.get(b.key) ?? 0));
    }
    const cursor = this.rr.get(match.route) ?? 0;
    this.rr.set(match.route, (cursor + 1) % targets.length);
    return [...targets.slice(cursor), ...targets.slice(0, cursor)];
  }

  acquire(target: Target): void {
    this.active.set(target.key, (this.active.get(target.key) ?? 0) + 1);
  }

  release(target: Target): void {
    const next = (this.active.get(target.key) ?? 1) - 1;
    if (next <= 0) this.active.delete(target.key);
    else this.active.set(target.key, next);
  }

  private modeFor(route: Route): BackendMode | "inherit" {
    if (route.backendMode !== "inherit") return route.backendMode;
    const name = route.serverNames[0];
    if (!name) return "inherit";
    return this.servers.get(name)?.backendMode ?? "inherit";
  }

  private unmatched(sni: string): Match {
    const spec = this.config.unmatched as string;
    const route: Route = {
      name: "unmatched",
      hosts: ["*"],
      backends: [spec],
      serverNames: [],
      strategy: "first",
      backendMode: "inherit",
      intercept: false,
      tls: { rejectUnauthorized: true },
      binds: [],
    };
    const captures: Captures = { sni, groups: [sni] };
    return {
      route,
      captures,
      targets: this.targetsFor(route, captures),
      reason: "unmatched",
      backendMode: "inherit",
    };
  }

  private targetsFor(route: Route, captures: Captures): Target[] {
    if (route.serverNames.length > 0) {
      const targets: Target[] = [];
      for (const name of route.serverNames) {
        const server = this.servers.get(name);
        if (!server) throw new Error(`route ${route.name} points at unknown server ${name}`);
        for (const address of server.addresses) targets.push(concrete(address));
      }
      return targets;
    }
    return route.backends.map((backend) => concrete(parseAddress(substitute(backend, captures), `backend ${JSON.stringify(backend)}`)));
  }
}

export function substitute(template: string, captures: Captures): string {
  return template.replace(/\$\{sni\}|\$\{host\}|\$(\d+)/g, (token, index: string | undefined) => {
    if (token === "${sni}" || token === "${host}") return captures.sni;
    const at = Number(index);
    if (at === 0) return captures.sni;
    const value = captures.groups[at - 1];
    if (value === undefined) {
      throw new Error(`backend ${JSON.stringify(template)} uses ${token}, but the host only captured ${captures.groups.length} group(s)`);
    }
    return value;
  });
}

export function hostMatches(pattern: string, host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  if (!normalized) return false;
  return compileHost(pattern).test(normalized);
}

function compileHost(pattern: string): RegExp {
  const normalized = pattern.trim().toLowerCase().replace(/\.$/, "");
  if (normalized === "*") return /^(.+)$/;
  const parts = normalized.split(".").map((label) => {
    if (label === "*") return "([^.]+)";
    if (label === "**") return "(.+)";
    return label.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  });
  return new RegExp(`^${parts.join("\\.")}$`);
}

function concrete(address: Address): Target {
  return { ...address, key: formatAddress(address) };
}

function shuffle<T>(items: T[]): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j]!, copy[i]!];
  }
  return copy;
}

export function strategyOf(value: string, path: string): Strategy {
  if (value === "first" || value === "round-robin" || value === "random" || value === "least-connections") return value;
  throw new Error(`${path} strategy must be first, round-robin, random, or least-connections`);
}

export function isBackendAddress(value: string): boolean {
  return looksLikeAddress(value);
}
