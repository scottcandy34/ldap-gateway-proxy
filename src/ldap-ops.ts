import { integer, octet, readInteger, readLength, readString, readTlv, tlv, type Tlv } from "./ber.js";
import { filterFromBer, filterToBer } from "./filter.js";
import type { ScopeName } from "./types.js";

export const SUCCESS = 0;
export const OPERATIONS_ERROR = 1;
export const WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3";

const OP_BIND = 0x60;
const OP_SEARCH = 0x63;
const OP_UNBIND = 0x42;
const OP_ABANDON = 0x50;
const OP_EXTENDED = 0x77;

export type LdapMessage = {
  end: number;
  id: number;
  opTag: number;
  op: Buffer;
  controls: boolean;
};

export type BindRequest = { dn: string; password: string; sasl: boolean };
export type SearchRequest = {
  base: string;
  scope: ScopeName;
  filter: string;
  attributes: string[];
  typesOnly: boolean;
  sizeLimit: number;
  timeLimit: number;
};

export function parseMessage(buf: Buffer, maxBytes: number): LdapMessage | "need" | "bad" {
  if (buf.length >= 2) {
    const declared = declaredSize(buf);
    if (declared === "bad") return "bad";
    if (typeof declared === "number" && declared > maxBytes) return "bad";
  }
  const message = readTlv(buf, 0);
  if (message === "need") return "need";
  if (message === "bad" || message.tag !== 0x30) return "bad";
  const id = readTlv(buf, message.valueStart);
  if (id === "need" || id === "bad" || id.tag !== 0x02) return "bad";
  const op = readTlv(buf, id.end);
  if (op === "need" || op === "bad") return "bad";
  return {
    end: message.end,
    id: readInteger(buf.subarray(id.valueStart, id.end)),
    opTag: op.tag,
    op: buf.subarray(op.start, op.end),
    controls: op.end < message.end,
  };
}

export function parseBind(op: Buffer): BindRequest {
  const body = readTlv(op, 0);
  if (body === "need" || body === "bad" || body.tag !== OP_BIND) throw new Error("not a bind request");
  const fields = children(op, body);
  const auth = fields[2];
  if (!auth) throw new Error("bind request is missing credentials");
  return {
    dn: text(op, fields[1]),
    password: auth.tag === 0x80 ? op.toString("utf8", auth.valueStart, auth.end) : "",
    sasl: auth.tag !== 0x80,
  };
}

export function parseSearch(op: Buffer): SearchRequest {
  const body = readTlv(op, 0);
  if (body === "need" || body === "bad" || body.tag !== OP_SEARCH) throw new Error("not a search request");
  const fields = children(op, body);
  const filter = fields[6];
  if (!filter) throw new Error("search request is missing a filter");
  const attributes = fields[7] ? children(op, fields[7]).map((field) => text(op, field).toLowerCase()) : [];
  return {
    base: text(op, fields[0]),
    scope: scopeName(op[fields[1]?.valueStart ?? 0] ?? 0),
    filter: filterFromBer(op, filter.start).text,
    attributes,
    typesOnly: (op[fields[5]?.valueStart ?? 0] ?? 0) !== 0,
    sizeLimit: fields[3] ? readInteger(op.subarray(fields[3].valueStart, fields[3].end)) : 0,
    timeLimit: fields[4] ? readInteger(op.subarray(fields[4].valueStart, fields[4].end)) : 0,
  };
}

export function bindRequest(id: number, dn: string, password: string): Buffer {
  const op = tlv(OP_BIND, Buffer.concat([integer(3), octet(dn), tlv(0x80, Buffer.from(password))]));
  return wrap(id, op);
}

export function bindResponse(id: number, code: number, diagnostic = ""): Buffer {
  return wrap(id, result(0x61, code, diagnostic));
}

export function searchRequest(id: number, base: string, scope: ScopeName, filter: string): Buffer {
  const scopeCode = scope === "base" ? 0 : scope === "one" ? 1 : 2;
  const op = tlv(OP_SEARCH, Buffer.concat([
    octet(base),
    tlv(0x0a, Buffer.from([scopeCode])),
    tlv(0x0a, Buffer.from([0])),
    integer(0),
    integer(0),
    tlv(0x01, Buffer.from([0])),
    filterToBer(filter),
    tlv(0x30, Buffer.alloc(0)),
  ]));
  return wrap(id, op);
}

export function searchDone(id: number, code = SUCCESS, diagnostic = ""): Buffer {
  return wrap(id, result(0x65, code, diagnostic));
}

export function searchEntry(id: number, dn: string, attributes: Record<string, string[]>): Buffer {
  const encoded = Object.entries(attributes).map(([name, values]) => {
    const vals = tlv(0x31, Buffer.concat(values.map((value) => octet(value))));
    return tlv(0x30, Buffer.concat([octet(name), vals]));
  });
  const op = tlv(0x64, Buffer.concat([octet(dn), tlv(0x30, Buffer.concat(encoded))]));
  return wrap(id, op);
}

export function whoamiResponse(id: number, dn: string | null): Buffer {
  const authz = dn && dn.length > 0 ? Buffer.from(`dn:${dn}`) : Buffer.alloc(0);
  const op = tlv(0x78, Buffer.concat([
    tlv(0x0a, Buffer.from([SUCCESS])),
    octet(""),
    octet(""),
    tlv(0x8b, authz),
  ]));
  return wrap(id, op);
}

export function operationsError(id: number, tag: number, diagnostic: string): Buffer {
  const response = tag === OP_BIND ? 0x61 : tag === OP_SEARCH ? 0x65 : tag === OP_EXTENDED ? 0x78 : 0x65;
  return wrap(id, result(response, OPERATIONS_ERROR, diagnostic));
}

export function isUnbind(tag: number): boolean {
  return tag === OP_UNBIND;
}

export function isAbandon(tag: number): boolean {
  return tag === OP_ABANDON;
}

export function isWhoami(op: Buffer): boolean {
  const body = readTlv(op, 0);
  if (body === "need" || body === "bad" || body.tag !== OP_EXTENDED) return false;
  const oid = readTlv(op, body.valueStart);
  if (oid === "need" || oid === "bad" || oid.tag !== 0x80) return false;
  return op.toString("utf8", oid.valueStart, oid.end) === WHOAMI_OID;
}

export function isSearch(tag: number): boolean {
  return tag === OP_SEARCH;
}

export function isBind(tag: number): boolean {
  return tag === OP_BIND;
}

export function terminalResponse(requestTag: number): number | undefined {
  const map: Record<number, number> = {
    0x60: 0x61,
    0x63: 0x65,
    0x66: 0x67,
    0x68: 0x69,
    0x4a: 0x6b,
    0x6c: 0x6d,
    0x6e: 0x6f,
    0x77: 0x78,
  };
  return map[requestTag];
}

export function withId(id: number, op: Buffer): Buffer {
  return wrap(id, op);
}

export function resultCode(op: Buffer): number | undefined {
  const body = readTlv(op, 0);
  if (body === "need" || body === "bad") return;
  const code = readTlv(op, body.valueStart);
  if (code === "need" || code === "bad" || code.tag !== 0x0a) return;
  return op[code.valueStart];
}

export function scopeName(code: number): ScopeName {
  if (code === 0) return "base";
  if (code === 1) return "one";
  return "sub";
}

export function scopeOf(value: string): ScopeName {
  const name = value.trim().toLowerCase();
  if (name === "base") return "base";
  if (name === "one" || name === "onelevel") return "one";
  if (name === "sub" || name === "subtree") return "sub";
  throw new Error(`scope must be base, one, or subtree (got ${value})`);
}

function wrap(id: number, op: Buffer): Buffer {
  return tlv(0x30, Buffer.concat([integer(id), op]));
}

function result(tag: number, code: number, diagnostic: string): Buffer {
  return tlv(tag, Buffer.concat([tlv(0x0a, Buffer.from([code])), octet(""), octet(diagnostic)]));
}

function children(buf: Buffer, field: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let offset = field.valueStart;
  while (offset < field.end) {
    const child = readTlv(buf, offset);
    if (child === "need" || child === "bad") throw new Error("truncated LDAP field");
    out.push(child);
    offset = child.end;
  }
  return out;
}

function text(buf: Buffer, field: Tlv | undefined): string {
  if (!field) return "";
  return readString(buf, field);
}

function declaredSize(buf: Buffer): number | "need" | "bad" {
  const length = readLength(buf, 1);
  if (length === "need" || length === "bad") return length;
  return length.valueStart + length.value;
}
