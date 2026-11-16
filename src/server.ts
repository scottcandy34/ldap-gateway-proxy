import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer, connect as netConnect, type Server, type Socket } from "node:net";
import { extendedResult, inspectLdap, startTlsRequest } from "./ldap.js";
import { createLogger, type Logger } from "./log.js";
import { Router, type Match, type Target } from "./router.js";
import { inspectClientHello } from "./sni.js";
import type { BackendMode, Config, Listener } from "./types.js";

const HELLO_LIMIT = 64 * 1024;

export type Running = {
  listeners: Array<{ host: string; port: number; mode: Listener["mode"] }>;
  healthPort?: number;
  close: () => Promise<void>;
};

export async function startProxy(config: Config, logger?: Logger): Promise<Running> {
  const log = logger ?? createLogger(config.log.level, config.log.format);
  const router = new Router(config);
  const sockets = new Set<Socket>();
  const servers: Array<Server | HttpServer> = [];
  let connections = 0;
  let closing = false;

  function track(socket: Socket): boolean {
    if (closing || connections >= config.limits.maxConnections) {
      if (!closing) log.warn("rejecting connection, limit reached", { limit: config.limits.maxConnections });
      socket.destroy();
      return false;
    }
    connections += 1;
    sockets.add(socket);
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30_000);
    socket.on("error", (error) => log.debug("socket error", { error: error.message }));
    socket.once("close", () => {
      connections -= 1;
      sockets.delete(socket);
    });
    return true;
  }

  async function accept(socket: Socket, listener: Listener): Promise<void> {
    socket.setTimeout(config.timeouts.handshakeMs);
    socket.on("timeout", () => socket.destroy());
    try {
      if (listener.mode === "ldaps") await serveLdaps(socket, listener);
      else await serveStartTls(socket, listener);
    } catch (error) {
      log.warn("connection closed", { error: error instanceof Error ? error.message : String(error) });
      socket.destroy();
    }
  }

  async function serveLdaps(socket: Socket, listener: Listener): Promise<void> {
    const hello = await readHello(socket);
    const denied = denial(config, router, hello.sni);
    if (denied) {
      log.warn("rejected", { sni: hello.sni ?? "", error: denied });
      socket.destroy();
      return;
    }
    const match = router.match(hello.sni);
    if (!match || match.targets.length === 0) {
      log.warn("rejected", { sni: hello.sni ?? "", error: `no LDAP route for ${hello.sni || "this connection"}` });
      socket.destroy();
      return;
    }
    const mode = resolveMode(match, listener);
    const backend = await dial(router, match, config, log);
    if (mode === "starttls") await completeStartTls(backend.socket);
    backend.socket.write(hello.bytes);
    bridge(socket, backend.socket, config.timeouts.idleMs);
    watch(router, backend.target, socket, backend.socket);
    log.info("proxied", { sni: hello.sni ?? "", route: match.route.name, backend: backend.target.key, mode, pattern: match.reason });
  }

  async function serveStartTls(socket: Socket, listener: Listener): Promise<void> {
    const request = await readLdap(socket);
    if (!request.view.startTls) {
      log.warn("rejected", { error: "StartTLS is required" });
      socket.end(extendedResult(request.view.messageId, 2));
      return;
    }
    socket.write(extendedResult(request.view.messageId, 0));
    const hello = await readHello(socket);
    const denied = denial(config, router, hello.sni);
    if (denied) {
      log.warn("rejected", { sni: hello.sni ?? "", error: denied });
      socket.destroy();
      return;
    }
    const match = router.match(hello.sni);
    if (!match || match.targets.length === 0) {
      log.warn("rejected", { sni: hello.sni ?? "", error: `no LDAP route for ${hello.sni || "this connection"}` });
      socket.destroy();
      return;
    }
    const mode = resolveMode(match, listener);
    const backend = await dial(router, match, config, log);
    if (mode === "starttls") await completeStartTls(backend.socket);
    backend.socket.write(hello.bytes);
    bridge(socket, backend.socket, config.timeouts.idleMs);
    watch(router, backend.target, socket, backend.socket);
    log.info("proxied", { sni: hello.sni ?? "", route: match.route.name, backend: backend.target.key, mode, pattern: match.reason });
  }

  for (const listener of config.listeners) {
    const server = createServer((socket) => {
      if (!track(socket)) return;
      void accept(socket, listener);
    });
    await listen(server, listener.host, listener.port);
    servers.push(server);
    const bound = server.address();
    if (bound && typeof bound !== "string") listener.port = bound.port;
  }

  let healthPort: number | undefined;
  if (config.health.enabled) {
    const health = createHttpServer((request, response) => {
      if (request.url !== "/health" && request.url !== "/") {
        response.writeHead(404);
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, connections, routes: config.routes.length }));
    });
    await listen(health, config.health.host, config.health.port);
    servers.push(health);
    const bound = health.address();
    healthPort = bound && typeof bound !== "string" ? bound.port : undefined;
  }

  const listeners = config.listeners.map((listener) => ({ host: listener.host, port: listener.port, mode: listener.mode }));
  log.info("listening", {
    bind: listeners.map((listener) => `${listener.mode}://${listener.host}:${listener.port}`).join(","),
    routes: config.routes.length,
    requireSni: config.requireSni,
    blockIpSni: config.blockIpSni,
    health: healthPort ? `${config.health.host}:${healthPort}` : "off",
  });
  if (config.routes.length === 0 && config.unmatched === "reject") {
    log.warn("no routes configured; every hostname will be rejected until you edit the config");
  }
  for (const route of config.routes) {
    log.info("route", {
      name: route.name,
      host: route.hosts.join(","),
      backend: route.backends.length > 0 ? route.backends.join(",") : route.serverNames.join(","),
    });
  }

  return {
    listeners,
    healthPort,
    close: async () => {
      closing = true;
      await Promise.all(servers.map((server) => closeServer(server)));
      for (const socket of sockets) socket.destroy();
    },
  };
}

async function completeStartTls(backend: Socket): Promise<void> {
  const pending = readLdap(backend);
  backend.write(startTlsRequest(1));
  const reply = await pending;
  if (reply.view.resultCode !== 0) {
    throw new Error(`backend refused StartTLS (${reply.view.resultCode ?? "no result"})`);
  }
}

function resolveMode(match: Match, listener: Listener): BackendMode {
  return match.backendMode === "inherit" ? listener.mode : match.backendMode;
}

function denial(config: Config, router: Router, serverName: string | undefined): string | undefined {
  const host = router.normalize(serverName);
  if (!host) {
    if (config.requireSni) return "server name indication (SNI) is required; connect with a hostname, not a raw IP";
    return;
  }
  if (config.blockIpSni && router.isIp(host)) return "connections by IP address are not accepted";
  return;
}

async function dial(router: Router, match: Match, config: Config, log: Logger): Promise<{ socket: Socket; target: Target }> {
  let last: Error | undefined;
  for (const target of router.order(match)) {
    try {
      const socket = await connectBackend(target, config.timeouts.connectMs);
      return { socket, target };
    } catch (error) {
      last = error instanceof Error ? error : new Error(String(error));
      log.warn("backend attempt failed", { backend: target.key, error: last.message });
    }
  }
  throw last ?? new Error("no backends configured");
}

function connectBackend(target: Target, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: target.host, port: target.port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect ${target.key} timed out`));
    }, timeoutMs);
    const fail = (error: Error) => {
      clearTimeout(timer);
      reject(error);
    };
    socket.once("error", fail);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.off("error", fail);
      socket.on("error", () => socket.destroy());
      socket.setTimeout(0);
      resolve(socket);
    });
  });
}

type HelloRead = { sni?: string; bytes: Buffer };

function readHello(socket: Socket): Promise<HelloRead> {
  return readUntil(socket, (buf) => {
    const view = inspectClientHello(buf);
    if (view.state === "need") return;
    if (view.state === "bad") throw new Error(view.reason);
    return { sni: view.sni, bytes: buf };
  });
}

type LdapRead = { view: Extract<ReturnType<typeof inspectLdap>, { state: "ok" }>; bytes: Buffer };

function readLdap(socket: Socket): Promise<LdapRead> {
  return readUntil(socket, (buf) => {
    const view = inspectLdap(buf);
    if (view.state === "need") return;
    if (view.state === "bad") throw new Error(view.reason);
    if (view.end < buf.length) {
      socket.pause();
      socket.unshift(buf.subarray(view.end));
    }
    return { view, bytes: buf.subarray(0, view.end) };
  });
}

function readUntil<T>(socket: Socket, step: (buf: Buffer) => T | undefined): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let settled = false;
    const finish = (error: Error | null, value?: T) => {
      if (settled) return;
      settled = true;
      socket.pause();
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
      if (error) reject(error);
      else resolve(value as T);
    };
    const onError = (error: Error) => finish(error);
    const onClose = () => finish(new Error("connection closed before the handshake finished"));
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length > HELLO_LIMIT) return finish(new Error("handshake is too large"));
      try {
        const value = step(buf);
        if (value !== undefined) finish(null, value);
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    };
    socket.resume();
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

function bridge(client: Socket, backend: Socket, idleMs: number): void {
  client.setTimeout(idleMs);
  backend.setTimeout(idleMs);
  const fail = () => {
    client.destroy();
    backend.destroy();
  };
  client.on("timeout", fail);
  backend.on("timeout", fail);
  client.pipe(backend);
  backend.pipe(client);
  client.on("close", () => backend.destroy());
  backend.on("close", () => client.destroy());
  client.on("error", fail);
  backend.on("error", fail);
}

function watch(router: Router, target: Target, client: Socket, backend: Socket): void {
  router.acquire(target);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    router.release(target);
  };
  client.once("close", release);
  backend.once("close", release);
}

function listen(server: Server | HttpServer, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

function closeServer(server: Server | HttpServer): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}
