import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer as netCreateServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect as tlsConnect, createServer as tlsCreateServer, type TLSSocket } from "node:tls";
import { describe, it } from "node:test";
import { promisify } from "node:util";
import { parseConfig } from "../src/config.js";
import { canonicalFilter, filterFromBer, filterToBer } from "../src/filter.js";
import {
  bindRequest,
  bindResponse,
  isBind,
  isSearch,
  parseBind,
  parseMessage,
  parseSearch,
  resultCode,
  searchDone,
  searchEntry,
  searchRequest,
} from "../src/ldap-ops.js";
import { startProxy } from "../src/server.js";

const execFileAsync = promisify(execFile);

describe("filters", () => {
  it("canonicalizes and round-trips a present filter", () => {
    assert.equal(canonicalFilter("(objectClass=*)"), "(objectclass=*)");
    assert.equal(canonicalFilter("(&(objectClass=person)(cn=Ada))"), "(&(objectclass=person)(cn=Ada))");
    const encoded = filterToBer("(objectClass=*)");
    assert.equal(filterFromBer(encoded, 0).text, "(objectclass=*)");
  });
});

describe("firewall", () => {
  it("limits binds and searches, maps anonymous, and caches", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ldap-firewall-"));
    const material = await selfSigned(dir);
    const backend = await directory(material);
    const config = parseConfig(
      {
        listen: [{ bind: "127.0.0.1:0", mode: "ldaps" }],
        health: { enabled: false },
        firewall: { allowAllBinds: false, cache: { maxBytes: 1_000_000, ttl: "60s" } },
        routes: [
          {
            host: "ldap.test",
            backend: `127.0.0.1:${backend.port}`,
            mode: "ldaps",
            tls: { cert: material.certPath, key: material.keyPath, rejectUnauthorized: false },
            binds: {
              "cn=admin,dc=example,dc=com": {
                allowedQueries: [["", "base", "(cn=ada)"]],
              },
              "": {
                mapToDn: "uid=reader,dc=example,dc=com",
                mapToSecret: "secret",
                allowedQueries: [["dc=example,dc=com", "subtree", "(objectClass=*)"]],
              },
            },
          },
        ],
      },
      path.join(dir, "memory.yml"),
    );
    const proxy = await startProxy(config);
    const port = proxy.listeners[0]?.port;
    assert.ok(port);
    try {
      const denied = await ldap(port, "ldap.test");
      const deniedBind = await round(denied, bindRequest(1, "cn=nope,dc=example,dc=com", "secret"), 0x61);
      assert.equal(codeOf(deniedBind), 1);
      assert.deepEqual(backend.events, []);
      denied.destroy();

      const admin = await ldap(port, "ldap.test");
      assert.equal(codeOf(await round(admin, bindRequest(2, "cn=admin,dc=example,dc=com", "secret"), 0x61)), 0);
      assert.deepEqual(backend.events, ["bind cn=admin,dc=example,dc=com secret"]);
      const blocked = await round(admin, searchRequest(3, "dc=example,dc=com", "sub", "(objectClass=*)"), 0x65);
      assert.equal(blocked.length, 1);
      assert.equal(backend.searches, 0);
      const found = await round(admin, searchRequest(4, "", "base", "(cn=ada)"), 0x65);
      assert.equal(found.length, 2);
      assert.equal(backend.searches, 1);
      await round(admin, searchRequest(5, "", "base", "(cn=ada)"), 0x65);
      assert.equal(backend.searches, 1);
      admin.destroy();

      const anon = await ldap(port, "ldap.test");
      assert.equal(codeOf(await round(anon, bindRequest(1, "", "ignored"), 0x61)), 0);
      assert.equal(backend.events.at(-1), "bind uid=reader,dc=example,dc=com secret");
      anon.destroy();
    } finally {
      await proxy.close();
      await backend.close();
    }
  });

  it("terminates client TLS and speaks plaintext LDAP to the backend", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ldap-plain-"));
    const material = await selfSigned(dir);
    const backend = await plainDirectory();
    const config = parseConfig(
      {
        listen: [{ bind: "127.0.0.1:0", mode: "ldaps" }],
        health: { enabled: false },
        firewall: { allowAllBinds: true, cache: { maxBytes: 0, ttl: "60s" } },
        routes: [
          {
            host: "ldap.test",
            backend: `127.0.0.1:${backend.port}`,
            mode: "plain",
            tls: { cert: material.certPath, key: material.keyPath },
          },
        ],
      },
      path.join(dir, "memory.yml"),
    );
    assert.equal(config.routes[0]?.intercept, true);
    const proxy = await startProxy(config);
    const port = proxy.listeners[0]?.port;
    assert.ok(port);
    try {
      const client = await ldap(port, "ldap.test");
      assert.equal(codeOf(await round(client, bindRequest(1, "cn=admin,dc=example,dc=com", "secret"), 0x61)), 0);
      assert.deepEqual(backend.events, ["bind cn=admin,dc=example,dc=com secret"]);
      client.destroy();
    } finally {
      await proxy.close();
      await backend.close();
    }
  });
});

function codeOf(messages: Buffer[]): number | undefined {
  const parsed = parseMessage(messages[0] ?? Buffer.alloc(0), 1_000_000);
  if (parsed === "need" || parsed === "bad") return;
  return resultCode(parsed.op);
}

async function round(socket: TLSSocket, request: Buffer, terminal: number): Promise<Buffer[]> {
  socket.write(request);
  const messages: Buffer[] = [];
  let buffered = Buffer.alloc(0);
  for (;;) {
    const parsed = parseMessage(buffered, 1_000_000);
    if (parsed !== "need" && parsed !== "bad") {
      messages.push(buffered.subarray(0, parsed.end));
      buffered = buffered.subarray(parsed.end);
      if (parsed.opTag === terminal) return messages;
      continue;
    }
    const [chunk] = (await once(socket, "data")) as [Buffer];
    buffered = Buffer.concat([buffered, chunk]);
  }
}

function ldap(port: number, servername: string): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: "127.0.0.1", port, servername, rejectUnauthorized: false });
    socket.once("secureConnect", () => resolve(socket));
    socket.once("error", reject);
  });
}

type Material = { cert: string; key: string; certPath: string; keyPath: string };
type Mock = { port: number; events: string[]; searches: number; close: () => Promise<void> };

function plainDirectory(): Promise<Mock> {
  const events: string[] = [];
  const server = netCreateServer((socket) => {
    socket.on("error", () => socket.destroy());
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const message = parseMessage(buffered, 1_000_000);
        if (message === "need" || message === "bad") return;
        buffered = buffered.subarray(message.end);
        if (!isBind(message.opTag)) continue;
        const bind = parseBind(message.op);
        events.push(`bind ${bind.dn} ${bind.password}`);
        socket.write(bindResponse(message.id, 0));
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("mock failed to bind");
      resolve({
        port: address.port,
        events,
        get searches() {
          return 0;
        },
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function directory(material: Material): Promise<Mock> {
  const events: string[] = [];
  const state = { searches: 0 };
  const server = tlsCreateServer({ cert: material.cert, key: material.key }, (socket) => {
    socket.on("error", () => socket.destroy());
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const message = parseMessage(buffered, 1_000_000);
        if (message === "need" || message === "bad") return;
        buffered = buffered.subarray(message.end);
        if (isBind(message.opTag)) {
          const bind = parseBind(message.op);
          events.push(`bind ${bind.dn} ${bind.password}`);
          const code = bind.password === "secret" ? 0 : 49;
          socket.write(bindResponse(message.id, code, code === 0 ? "" : "invalid"));
        } else if (isSearch(message.opTag)) {
          state.searches += 1;
          const search = parseSearch(message.op);
          events.push(`search ${search.filter}`);
          socket.write(searchEntry(message.id, "cn=ada,dc=example,dc=com", { cn: ["ada"] }));
          socket.write(searchDone(message.id, 0));
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("mock failed to bind");
      resolve({
        port: address.port,
        events,
        get searches() {
          return state.searches;
        },
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

async function selfSigned(dir: string): Promise<Material> {
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  await execFileAsync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "2", "-nodes", "-subj", "/CN=ldap.test",
  ]);
  return { cert: await readFile(certPath, "utf8"), key: await readFile(keyPath, "utf8"), certPath, keyPath };
}
