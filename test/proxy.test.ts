import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer, connect as netConnect, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect as tlsConnect, createSecureContext, TLSSocket, createServer as tlsCreateServer } from "node:tls";
import { describe, it } from "node:test";
import { promisify } from "node:util";
import { parseConfig } from "../src/config.js";
import { extendedResult, inspectLdap, startTlsRequest } from "../src/ldap.js";
import { startProxy, type Running } from "../src/server.js";

const execFileAsync = promisify(execFile);

describe("proxy", () => {
  it("routes LDAPS by SNI and refuses other names", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ldap-proxy-"));
    const material = await selfSigned(dir);
    const one = await ldapsBackend(material);
    const two = await ldapsBackend(material);
    let proxy: Running | undefined;
    try {
      proxy = await boot([
        { name: "one", host: "one.test", backend: `127.0.0.1:${one.port}` },
        { name: "two", host: "two.test", backend: `127.0.0.1:${two.port}`, mode: "ldaps" },
      ]);
      const ldaps = proxy.listeners.find((listener) => listener.mode === "ldaps");
      assert.ok(ldaps);
      await ldapsClient(ldaps.port, "one.test");
      await ldapsClient(ldaps.port, "two.test");
      assert.deepEqual(one.names, ["one.test"]);
      assert.deepEqual(two.names, ["two.test"]);
      await assert.rejects(ldapsClient(ldaps.port, "nope.test"));
      await assert.rejects(ldapsClient(ldaps.port));
      assert.deepEqual(one.names, ["one.test"]);
      const health = await fetch(`http://127.0.0.1:${proxy.healthPort}/health`);
      assert.equal(health.status, 200);
    } finally {
      await proxy?.close();
      await one.close();
      await two.close();
    }
  });

  it("routes StartTLS after the LDAP exchange", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ldap-proxy-"));
    const material = await selfSigned(dir);
    const backend = await startTlsBackend(material);
    let proxy: Running | undefined;
    try {
      proxy = await boot([{ host: "ldap.test", backend: `127.0.0.1:${backend.port}`, mode: "starttls" }]);
      const plain = proxy.listeners.find((listener) => listener.mode === "starttls");
      assert.ok(plain);
      await startTlsClient(plain.port, "ldap.test");
      assert.deepEqual(backend.names, ["ldap.test"]);
      await assert.rejects(startTlsClient(plain.port, "other.test"));
      assert.deepEqual(backend.names, ["ldap.test"]);
    } finally {
      await proxy?.close();
      await backend.close();
    }
  });

  it("answers a plain LDAP port with StartTLS and still reaches an LDAPS backend", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ldap-proxy-"));
    const material = await selfSigned(dir);
    const backend = await ldapsBackend(material);
    let proxy: Running | undefined;
    try {
      proxy = await boot([{ host: "ldap.test", backend: `127.0.0.1:${backend.port}`, mode: "ldaps" }]);
      const plain = proxy.listeners.find((listener) => listener.mode === "starttls");
      assert.ok(plain);
      await startTlsClient(plain.port, "ldap.test");
      assert.deepEqual(backend.names, ["ldap.test"]);
    } finally {
      await proxy?.close();
      await backend.close();
    }
  });

  it("drops garbage on the LDAPS port without exiting", async () => {
    let proxy: Running | undefined;
    try {
      proxy = await boot([{ host: "ldap.test", backend: "127.0.0.1:1" }]);
      const ldaps = proxy.listeners.find((listener) => listener.mode === "ldaps");
      assert.ok(ldaps);
      await new Promise<void>((resolve) => {
        const socket = netConnect({ host: "127.0.0.1", port: ldaps.port });
        socket.on("error", () => resolve());
        socket.on("close", () => resolve());
        socket.on("connect", () => socket.write(Buffer.from("GET / HTTP/1.0\r\n\r\n")));
      });
      const health = await fetch(`http://127.0.0.1:${proxy.healthPort}/health`);
      assert.equal(health.status, 200);
    } finally {
      await proxy?.close();
    }
  });
});

async function boot(routes: unknown[]): Promise<Running> {
  const config = parseConfig(
    {
      listen: [
        { bind: "127.0.0.1:0", mode: "ldaps" },
        { bind: "127.0.0.1:0", mode: "starttls" },
      ],
      requireSni: true,
      blockIpSni: true,
      health: { enabled: true, bind: "127.0.0.1:0" },
      timeouts: { connect: "1s", handshake: "2s", idle: "0s" },
      routes,
    },
    "memory.yml",
  );
  return startProxy(config);
}

function ldapsClient(port: number, servername?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: "127.0.0.1", port, servername, rejectUnauthorized: false });
    socket.once("data", () => {
      socket.end();
      resolve();
    });
    socket.once("error", reject);
  });
}

async function startTlsClient(port: number, servername: string): Promise<void> {
  const socket = netConnect({ host: "127.0.0.1", port });
  await once(socket, "connect");
  socket.write(startTlsRequest(7));
  const reply = await readLdap(socket);
  assert.equal(reply.resultCode, 0);
  assert.equal(reply.messageId, 7);
  await new Promise<void>((resolve, reject) => {
    const secure = tlsConnect({ socket, servername, rejectUnauthorized: false });
    secure.once("data", () => {
      secure.end();
      resolve();
    });
    secure.once("error", reject);
  });
}

function readLdap(socket: Socket): Promise<{ messageId: number; resultCode?: number }> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => reject(new Error("timed out waiting for LDAP")), 2000);
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const view = inspectLdap(Buffer.concat(chunks));
      if (view.state === "need") return;
      clearTimeout(timer);
      socket.off("data", onData);
      if (view.state === "bad") {
        reject(new Error(view.reason));
        return;
      }
      resolve({ messageId: view.messageId, resultCode: view.resultCode });
    };
    socket.on("data", onData);
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

type Material = { cert: string; key: string };
type Mock = { port: number; names: string[]; close: () => Promise<void> };

function ldapsBackend(material: Material): Promise<Mock> {
  const names: string[] = [];
  const server = tlsCreateServer({ cert: material.cert, key: material.key }, (socket) => {
    names.push(socket.servername ?? "");
    socket.write("ok");
    socket.end();
  });
  server.on("tlsClientError", () => undefined);
  return bound(server, names);
}

function startTlsBackend(material: Material): Promise<Mock> {
  const names: string[] = [];
  const server = createServer((socket) => {
    socket.on("error", () => socket.destroy());
    const chunks: Buffer[] = [];
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      const view = inspectLdap(buf);
      if (view.state !== "ok") return;
      socket.off("data", onData);
      if (!view.startTls) {
        socket.destroy();
        return;
      }
      if (view.end < buf.length) {
        socket.pause();
        socket.unshift(buf.subarray(view.end));
      }
      socket.write(extendedResult(view.messageId, 0));
      const secure = new TLSSocket(socket, {
        isServer: true,
        secureContext: createSecureContext({ cert: material.cert, key: material.key }),
      });
      secure.on("error", () => secure.destroy());
      secure.once("secure", () => {
        names.push(secure.servername ?? "");
        secure.write("ok");
        secure.end();
      });
    };
    socket.on("data", onData);
  });
  return bound(server, names);
}

function bound(server: Server, names: string[]): Promise<Mock> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("mock failed to bind");
      resolve({
        port: address.port,
        names,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

async function selfSigned(dir: string): Promise<Material> {
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  await execFileAsync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "2", "-nodes", "-subj", "/CN=ldap",
  ]);
  return { cert: await readFile(cert, "utf8"), key: await readFile(key, "utf8") };
}
