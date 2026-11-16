export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFormat = "text" | "json";
export type Strategy = "first" | "round-robin" | "random" | "least-connections";
export type ListenMode = "ldaps" | "starttls";
export type BackendMode = "ldaps" | "starttls";

export type Address = {
  host: string;
  port: number;
};

export type Listener = {
  host: string;
  port: number;
  mode: ListenMode;
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
  servers: ServerDef[];
  routes: Route[];
};
