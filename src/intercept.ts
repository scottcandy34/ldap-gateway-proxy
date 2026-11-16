import { once } from "node:events";
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, createSecureContext, TLSSocket } from "node:tls";
import { SearchCache } from "./cache.js";
import { BindMap, queryKey } from "./firewall.js";
import type { Logger } from "./log.js";
import {
  OPERATIONS_ERROR,
  SUCCESS,
  bindRequest,
  bindResponse,
  isAbandon,
  isBind,
  isSearch,
  isUnbind,
  isWhoami,
  operationsError,
  parseBind,
  parseMessage,
  parseSearch,
  resultCode,
  searchDone,
  terminalResponse,
  whoamiResponse,
  withId,
  type LdapMessage,
} from "./ldap-ops.js";
import { startTlsRequest } from "./ldap.js";
import type { Router, Match, Target } from "./router.js";
import type { BackendMode, Config, Listener } from "./types.js";

const caches = new WeakMap<Config, SearchCache>();

export async function serveIntercept(options: {
  socket: Socket;
  hello: Buffer;
  match: Match;
  listener: Listener;
  config: Config;
  log: Logger;
  router: Router;
}): Promise<void> {
  const { socket, hello, match, listener, config, log, router } = options;
  const material = match.route.tls.cert && match.route.tls.key ? match.route.tls : listener.tls;
  if (!material.cert || !material.key) throw new Error(`route ${match.route.name} is missing tls.cert or tls.key`);
  socket.pause();
  socket.unshift(hello);
  const secure = new TLSSocket(socket, {
    isServer: true,
    secureContext: createSecureContext({ cert: material.cert, key: material.key }),
  });
  secure.on("error", () => secure.destroy());
  const session = new Session(secure, match, listener, config, log, router, cacheFor(config));
  await once(secure, "secure");
  await session.run();
}

function cacheFor(config: Config): SearchCache {
  let cache = caches.get(config);
  if (!cache) {
    cache = new SearchCache(config.firewall.cache.maxBytes, config.firewall.cache.ttlMs);
    caches.set(config, cache);
  }
  return cache;
}

class Session {
  private readonly reader: MessageReader;
  private readonly binds: BindMap;
  private backend: Directory | undefined;
  private clientDn: string | null = null;

  constructor(
    private readonly client: TLSSocket,
    private readonly match: Match,
    private readonly listener: Listener,
    private readonly config: Config,
    private readonly log: Logger,
    private readonly router: Router,
    private readonly cache: SearchCache,
  ) {
    this.reader = new MessageReader(client, config.firewall.maxIncomingBytes);
    this.binds = new BindMap(match.route.binds);
    client.setTimeout(config.timeouts.idleMs);
    client.on("timeout", () => client.destroy());
  }

  async run(): Promise<void> {
    try {
      for (;;) {
        const message = await this.reader.read();
        if (isUnbind(message.opTag)) return;
        if (isAbandon(message.opTag)) continue;
        if (isBind(message.opTag)) {
          await this.bind(message);
          continue;
        }
        if (isWhoami(message.op)) {
          this.send(whoamiResponse(message.id, this.clientDn));
          continue;
        }
        if (this.clientDn === null && isSearch(message.opTag)) {
          const bound = await this.bindUpstream("", "", null);
          if (!bound) {
            this.send(operationsError(message.id, message.opTag, "unable to bind"));
            continue;
          }
        }
        if (this.clientDn === null) {
          this.send(operationsError(message.id, message.opTag, "bind is required"));
          continue;
        }
        if (isSearch(message.opTag)) await this.search(message);
        else await this.forward(message);
      }
    } finally {
      this.client.destroy();
      this.backend?.close();
    }
  }

  private async bind(message: LdapMessage): Promise<void> {
    const request = parseBind(message.op);
    if (request.sasl) {
      this.send(bindResponse(message.id, OPERATIONS_ERROR, "only simple binds are supported"));
      return;
    }
    await this.bindUpstream(request.dn, request.password, message.id);
  }

  private async bindUpstream(dn: string, password: string, replyId: number | null): Promise<boolean> {
    const rule = this.binds.lookup(dn);
    if (!rule && !this.config.firewall.allowAllBinds) {
      this.log.warn("bind denied", { dn: dn || "anonymous", route: this.match.route.name });
      if (replyId !== null) this.send(bindResponse(replyId, OPERATIONS_ERROR, "unable to bind"));
      return false;
    }
    const directory = await this.directory();
    const upstreamDn = rule?.mapToDn ?? dn;
    const upstreamPassword = rule?.mapToSecret ?? password;
    const responses = await directory.request(bindRequest(1, upstreamDn, upstreamPassword), 0x61);
    const code = resultCode(responses[0] ?? Buffer.alloc(0));
    if (code !== SUCCESS) {
      this.clientDn = null;
      if (replyId !== null) this.send(bindResponse(replyId, code ?? OPERATIONS_ERROR, "unable to bind"));
      return false;
    }
    this.clientDn = dn;
    this.log.info("bind", { dn: dn || "anonymous", upstream: upstreamDn || "anonymous", route: this.match.route.name });
    if (replyId !== null) this.send(bindResponse(replyId, SUCCESS));
    return true;
  }

  private async search(message: LdapMessage): Promise<void> {
    const request = parseSearch(message.op);
    const query = { base: request.base, scope: request.scope, filter: request.filter };
    if (!this.binds.allows(this.clientDn ?? "", query, this.config.firewall.allowAllBinds)) {
      this.log.warn("search denied", { dn: this.clientDn || "anonymous", base: request.base, scope: request.scope, filter: request.filter });
      this.send(searchDone(message.id, SUCCESS));
      return;
    }
    const key = queryKey(this.clientDn ?? "", query);
    if (!message.controls) {
      const hit = this.cache.get(key);
      if (hit) {
        this.log.debug("cache hit", { dn: this.clientDn || "anonymous", filter: request.filter });
        for (const op of hit) this.send(withId(message.id, op));
        return;
      }
    }
    const directory = await this.directory();
    const terminal = terminalResponse(message.opTag);
    if (!terminal) throw new Error("search has no response");
    const responses = await directory.request(withId(message.id, message.op), terminal);
    const done = responses[responses.length - 1];
    if (!message.controls && done && resultCode(done) === SUCCESS) this.cache.set(key, responses);
    for (const op of responses) this.send(withId(message.id, op));
  }

  private async forward(message: LdapMessage): Promise<void> {
    const terminal = terminalResponse(message.opTag);
    if (!terminal) {
      this.send(operationsError(message.id, message.opTag, "unsupported LDAP operation"));
      return;
    }
    const directory = await this.directory();
    const responses = await directory.request(withId(message.id, message.op), terminal);
    for (const op of responses) this.send(withId(message.id, op));
  }

  private async directory(): Promise<Directory> {
    if (this.backend) return this.backend;
    let last: Error | undefined;
    const mode: BackendMode = this.match.backendMode === "inherit" ? this.listener.mode : this.match.backendMode;
    for (const target of this.router.order(this.match)) {
      try {
        const raw = await connectTcp(target, this.config.timeouts.connectMs);
        if (mode === "plain") {
          this.router.acquire(target);
          raw.once("close", () => this.router.release(target));
          this.backend = new Directory(raw, this.config.firewall.maxBackendBytes);
          return this.backend;
        }
        if (mode === "starttls") await openStartTls(raw);
        const secure = await openTls(raw, this.match.captures.sni, this.match.route.tls.ca, this.match.route.tls.rejectUnauthorized);
        this.router.acquire(target);
        secure.once("close", () => this.router.release(target));
        this.backend = new Directory(secure, this.config.firewall.maxBackendBytes);
        return this.backend;
      } catch (error) {
        last = error instanceof Error ? error : new Error(String(error));
        this.log.warn("backend attempt failed", { backend: target.key, error: last.message });
      }
    }
    throw last ?? new Error("no backends configured");
  }

  private send(message: Buffer): void {
    this.client.write(message);
  }
}

class Directory {
  private readonly reader: MessageReader;

  constructor(
    private readonly socket: Socket,
    maxBytes: number,
  ) {
    this.reader = new MessageReader(socket, maxBytes);
    socket.on("error", () => socket.destroy());
  }

  request(message: Buffer, terminal: number): Promise<Buffer[]> {
    const pending = this.collect(terminal);
    this.socket.write(message);
    return pending;
  }

  close(): void {
    this.socket.destroy();
  }

  private async collect(terminal: number): Promise<Buffer[]> {
    const ops: Buffer[] = [];
    for (;;) {
      const message = await this.reader.read();
      ops.push(message.op);
      if (message.opTag === terminal) return ops;
    }
  }
}

class MessageReader {
  private buffered = Buffer.alloc(0);
  private readonly waiting: Array<(value: LdapMessage | Error) => void> = [];
  private failed: Error | undefined;
  private readonly onData = (chunk: Buffer) => {
    this.buffered = Buffer.concat([this.buffered, chunk]);
    this.drain();
  };
  private readonly onError = (error: Error) => this.fail(error);
  private readonly onClose = () => this.fail(new Error("connection closed"));

  constructor(
    private readonly socket: Socket,
    private readonly maxBytes: number,
  ) {
    socket.on("data", this.onData);
    socket.on("error", this.onError);
    socket.on("close", this.onClose);
  }

  detach(): void {
    this.socket.off("data", this.onData);
    this.socket.off("error", this.onError);
    this.socket.off("close", this.onClose);
  }

  read(): Promise<LdapMessage> {
    const parsed = this.pull();
    if (parsed) return Promise.resolve(parsed);
    if (this.failed) return Promise.reject(this.failed);
    return new Promise((resolve, reject) => {
      this.waiting.push((value) => (value instanceof Error ? reject(value) : resolve(value)));
    });
  }

  private drain(): void {
    while (this.waiting.length > 0) {
      const message = this.pull();
      if (!message) return;
      this.waiting.shift()?.(message);
    }
  }

  private pull(): LdapMessage | undefined {
    if (this.buffered.length === 0) return;
    const parsed = parseMessage(this.buffered, this.maxBytes);
    if (parsed === "need") return;
    if (parsed === "bad") {
      this.fail(new Error("LDAP message exceeds the configured limit or is invalid"));
      return;
    }
    this.buffered = this.buffered.subarray(parsed.end);
    return parsed;
  }

  private fail(error: Error): void {
    if (this.failed) return;
    this.failed = error;
    while (this.waiting.length > 0) this.waiting.shift()?.(error);
  }
}

function connectTcp(target: Target, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: target.host, port: target.port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect ${target.key} timed out`));
    }, timeoutMs);
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.setTimeout(0);
      resolve(socket);
    });
  });
}

async function openStartTls(socket: Socket): Promise<void> {
  const reader = new MessageReader(socket, 1024 * 1024);
  socket.write(startTlsRequest(1));
  const reply = await reader.read();
  reader.detach();
  if (reply.opTag !== 0x78 || resultCode(reply.op) !== SUCCESS) throw new Error("backend refused StartTLS");
}

async function openTls(socket: Socket, servername: string, ca: string | undefined, rejectUnauthorized: boolean): Promise<TLSSocket> {
  const secure = tlsConnect({ socket, servername, ca, rejectUnauthorized });
  secure.on("error", () => secure.destroy());
  await once(secure, "secureConnect");
  return secure;
}
