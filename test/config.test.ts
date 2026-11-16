import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseConfig } from "../src/config.js";
import { extendedResult, inspectLdap, startTlsRequest } from "../src/ldap.js";

describe("config", () => {
  it("parses listeners, routes, and durations", () => {
    const config = parseConfig(
      {
        listen: [{ bind: "0.0.0.0:636", mode: "ldaps" }],
        requireSni: true,
        blockIpSni: true,
        routes: [{ host: "*.ldap.example.com", backend: "$1.internal:636", strategy: "round-robin" }],
        timeouts: { connect: "1500ms", handshake: "5s", idle: "0s" },
      },
      "memory.yml",
    );
    assert.equal(config.listeners[0]?.port, 636);
    assert.equal(config.routes[0]?.hosts[0], "*.ldap.example.com");
    assert.equal(config.timeouts.connectMs, 1500);
    assert.equal(config.timeouts.handshakeMs, 5000);
    assert.equal(config.timeouts.idleMs, 0);
  });

  it("rejects unknown keys", () => {
    assert.throws(() => parseConfig({ listen: [{ bind: "127.0.0.1:636", nope: true }] }, "memory.yml"), /unknown key/);
  });
});

describe("ldap messages", () => {
  it("round-trips a StartTLS request and a success result", () => {
    const request = inspectLdap(startTlsRequest(7));
    assert.equal(request.state, "ok");
    if (request.state !== "ok") return;
    assert.equal(request.startTls, true);
    assert.equal(request.messageId, 7);
    const result = inspectLdap(extendedResult(7, 0));
    assert.equal(result.state, "ok");
    if (result.state !== "ok") return;
    assert.equal(result.resultCode, 0);
    assert.equal(result.messageId, 7);
  });
});
