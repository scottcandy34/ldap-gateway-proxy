export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFormat = "text" | "json";
export type Strategy = "first" | "round-robin" | "random" | "least-connections";
export type ListenMode = "ldaps" | "starttls";
export type BackendMode = "ldaps" | "starttls" | "plain";
export type ScopeName = "base" | "one" | "sub";

export type Address = {
  host: string;
  port: number;
};

export type TlsMaterial = {
  cert?: string;
  key?: string;
  ca?: string;
  rejectUnauthorized: boolean;
};

export type Listener = {
  host: string;
  port: number;
  mode: ListenMode;
  tls: TlsMaterial;
};

export type AllowedQuery = {
  base: string;
  scope: ScopeName;
  filter: string;
};

export type BindRule = {
  dn: string;
  /** null means every search is allowed. */
  allowedQueries: AllowedQuery[] | null;
  mapToDn?: string;
  mapToSecret?: string;
};

export type ServerDef = {
  name: string;
  addresses: Address[];
  strategy: Strategy;
  backendMode: BackendMode | "inherit";
};

export type Route = {
  name: string;
  hosts: string[];
  backends: string[];
  serverNames: string[];
  strategy: Strategy;
  backendMode: BackendMode | "inherit";
  intercept: boolean;
  tls: TlsMaterial;
  binds: BindRule[];
};

export type Firewall = {
  allowAllBinds: boolean;
  maxIncomingBytes: number;
  maxBackendBytes: number;
  cache: { maxBytes: number; ttlMs: number };
};

export type Config = {
  configPath: string;
  listeners: Listener[];
  log: { level: LogLevel; format: LogFormat };
  limits: { maxConnections: number };
  timeouts: { connectMs: number; handshakeMs: number; idleMs: number };
  requireSni: boolean;
  blockIpSni: boolean;
  unmatched: "reject" | string;
  health: { enabled: boolean; host: string; port: number };
  firewall: Firewall;
  servers: ServerDef[];
  routes: Route[];
};
