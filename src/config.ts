import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import { parseAddress } from "./address.js";
import { isBackendAddress, strategyOf } from "./router.js";
import type { BackendMode, Config, ListenMode, Listener, LogFormat, LogLevel, Route, ServerDef } from "./types.js";

const DEFAULT_FILE = "config.default.yml";

export async function loadOrCreate(configPath: string): Promise<{ config: Config; created: boolean }> {
  try {
    const text = await readFile(configPath, "utf8");
    return { config: parseConfig(parse(text), configPath), created: false };
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : "";
    if (code !== "ENOENT") throw error;
    const seed = await readFile(path.resolve(DEFAULT_FILE), "utf8");
    await writeFile(configPath, seed);
    return { config: parseConfig(parse(seed), configPath), created: true };
  }
}

export function parseConfig(raw: unknown, configPath: string): Config {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("config must be a mapping");
  const doc = raw as Record<string, unknown>;
  assertKeys(doc, ["listen", "log", "limits", "timeouts", "requireSni", "blockIpSni", "unmatched", "health", "servers", "routes"], "config");
  const listeners = listenersOf(doc.listen);
  return {
    configPath,
    listeners,
    log: logOf(doc.log),
    limits: { maxConnections: positive(section(doc.limits, "limits").maxConnections ?? 2000, "limits.maxConnections") },
    timeouts: timeoutsOf(doc.timeouts),
    requireSni: bool(doc.requireSni, true),
    blockIpSni: bool(doc.blockIpSni, true),
    unmatched: unmatchedOf(doc.unmatched),
    health: healthOf(doc.health),
    servers: serversOf(doc.servers),
    routes: routesOf(doc.routes),
  };
}

function listenersOf(value: unknown): Listener[] {
  if (value === undefined) {
    return [
      { host: "0.0.0.0", port: 636, mode: "ldaps" },
      { host: "0.0.0.0", port: 389, mode: "starttls" },
    ];
  }
  if (!Array.isArray(value) || value.length === 0) throw new Error("listen must be a non-empty list");
  return value.map((item, index) => {
    const pathName = `listen[${index}]`;
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`${pathName} must be a mapping`);
    const doc = item as Record<string, unknown>;
    assertKeys(doc, ["bind", "mode"], pathName);
    const bind = typeof doc.bind === "string" ? parseAddress(doc.bind, `${pathName}.bind`) : undefined;
    if (!bind) throw new Error(`${pathName}.bind is required`);
    return { host: bind.host, port: bind.port, mode: modeOf(doc.mode, `${pathName}.mode`) };
  });
}

function logOf(value: unknown): Config["log"] {
  const doc = section(value, "log");
  assertKeys(doc, ["level", "format"], "log");
  const level = (doc.level as string | undefined) ?? "info";
  const format = (doc.format as string | undefined) ?? "text";
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") {
    throw new Error("log.level must be debug, info, warn, or error");
  }
  if (format !== "text" && format !== "json") throw new Error("log.format must be text or json");
  return { level: level as LogLevel, format: format as LogFormat };
}

function timeoutsOf(value: unknown): Config["timeouts"] {
  const doc = section(value, "timeouts");
  assertKeys(doc, ["connect", "handshake", "idle"], "timeouts");
  return {
    connectMs: duration(doc.connect ?? "5s", "timeouts.connect"),
    handshakeMs: duration(doc.handshake ?? "10s", "timeouts.handshake"),
    idleMs: duration(doc.idle ?? "0s", "timeouts.idle"),
  };
}

function healthOf(value: unknown): Config["health"] {
  const doc = section(value, "health");
  assertKeys(doc, ["enabled", "bind"], "health");
  const enabled = bool(doc.enabled, true);
  const bind = typeof doc.bind === "string" ? parseAddress(doc.bind, "health.bind") : parseAddress("127.0.0.1:8081", "health.bind");
  return { enabled, host: bind.host, port: bind.port };
}

function serversOf(value: unknown): ServerDef[] {
  if (value === undefined) return [];
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("servers must be a mapping");
  return Object.entries(value as Record<string, unknown>).map(([name, body]) => {
    const pathName = `servers.${name}`;
    if (typeof body === "string") {
      return { name, addresses: [parseAddress(body, pathName)], strategy: "first" as const, backendMode: "inherit" as const };
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error(`${pathName} must be host:port or a mapping`);
    const doc = body as Record<string, unknown>;
    assertKeys(doc, ["addresses", "strategy", "mode"], pathName);
    const addresses = listOf(doc.addresses, `${pathName}.addresses`).map((item) => parseAddress(item, `${pathName}.addresses`));
    if (addresses.length === 0) throw new Error(`${pathName}.addresses is empty`);
    return {
      name,
      addresses,
      strategy: strategyOf(typeof doc.strategy === "string" ? doc.strategy : "first", pathName),
      backendMode: doc.mode === undefined ? "inherit" : backendModeOf(doc.mode, `${pathName}.mode`),
    };
  });
}

function routesOf(value: unknown): Route[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("routes must be a list");
  return value.map((item, index) => {
    const pathName = `routes[${index}]`;
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`${pathName} must be a mapping`);
    const doc = item as Record<string, unknown>;
    assertKeys(doc, ["name", "host", "backend", "strategy", "mode"], pathName);
    const hosts = stringOrList(doc.host, `${pathName}.host`);
    if (hosts.length === 0) throw new Error(`${pathName}.host is required`);
    const backend = doc.backend;
    const route: Route = {
      name: typeof doc.name === "string" && doc.name ? doc.name : `route-${index + 1}`,
      hosts,
      backends: [],
      serverNames: [],
      strategy: strategyOf(typeof doc.strategy === "string" ? doc.strategy : "first", pathName),
      backendMode: doc.mode === undefined ? "inherit" : backendModeOf(doc.mode, `${pathName}.mode`),
    };
    const items = stringOrList(backend, `${pathName}.backend`);
    if (items.length === 0) throw new Error(`${pathName}.backend is required`);
    const addresses = items.filter((item) => isBackendAddress(item));
    if (addresses.length !== 0 && addresses.length !== items.length) {
      throw new Error(`${pathName}.backend cannot mix host:port values with server names`);
    }
    if (addresses.length === items.length) route.backends = items;
    else route.serverNames = items;
    return route;
  });
}

function unmatchedOf(value: unknown): Config["unmatched"] {
  if (value === undefined || value === "reject") return "reject";
  if (typeof value !== "string" || !value.trim()) throw new Error('unmatched must be "reject" or host:port');
  parseAddress(value, "unmatched");
  return value;
}

function modeOf(value: unknown, pathName: string): ListenMode {
  if (value === undefined) return "ldaps";
  if (value === "ldaps" || value === "starttls") return value;
  throw new Error(`${pathName} must be ldaps or starttls`);
}

function backendModeOf(value: unknown, pathName: string): BackendMode {
  if (value === "ldaps" || value === "starttls") return value;
  throw new Error(`${pathName} must be ldaps or starttls`);
}

function section(value: unknown, pathName: string): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${pathName} must be a mapping`);
  return value as Record<string, unknown>;
}

function assertKeys(doc: Record<string, unknown>, allowed: string[], pathName: string): void {
  for (const key of Object.keys(doc)) {
    if (!allowed.includes(key)) throw new Error(`${pathName} has unknown key ${key}`);
  }
}

function bool(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error("expected true or false");
  return value;
}

function positive(value: unknown, pathName: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(`${pathName} must be a positive integer`);
  }
  return value;
}

function duration(value: unknown, pathName: string): number {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  if (typeof value !== "string") throw new Error(`${pathName} must be a duration like 5s or 500ms`);
  const match = /^(\d+)(ms|s|m)?$/.exec(value.trim());
  if (!match) throw new Error(`${pathName} must be a duration like 5s or 500ms`);
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  if (unit === "ms") return amount;
  if (unit === "s") return amount * 1000;
  return amount * 60_000;
}

function stringOrList(value: unknown, pathName: string): string[] {
  if (typeof value === "string") return [value];
  if (value === undefined) return [];
  return listOf(value, pathName);
}

function listOf(value: unknown, pathName: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${pathName} must be a string or a list`);
  return value.map((item) => {
    if (typeof item !== "string" || !item.trim()) throw new Error(`${pathName} entries must be strings`);
    return item;
  });
}
