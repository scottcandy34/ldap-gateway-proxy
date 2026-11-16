/** StartTLS (RFC 4511 §4.14), just enough to spot the request and answer it. */

export const START_TLS_OID = Buffer.from([0x2b, 0x06, 0x01, 0x04, 0x01, 0x8b, 0x3a, 0x81, 0x9c, 0x45]);

export type LdapView =
  | { state: "need" }
  | { state: "bad"; reason: string }
  | { state: "ok"; end: number; messageId: number; op: number; startTls: boolean; resultCode?: number };

type Tlv = { tag: number; valueStart: number; end: number };

export function inspectLdap(buf: Buffer): LdapView {
  const message = readTlv(buf, 0);
  if (message === "need") return { state: "need" };
  if (message === "bad") return { state: "bad", reason: "invalid LDAP message" };
  if (message.tag !== 0x30) return { state: "bad", reason: "LDAP message is not a sequence" };
  const id = readTlv(buf, message.valueStart);
  if (id === "need" || id === "bad" || id.tag !== 0x02 || id.end > message.end) {
    return { state: "bad", reason: "LDAP message has no id" };
  }
  const messageId = readInteger(buf.subarray(id.valueStart, id.end));
  const op = readTlv(buf, id.end);
  if (op === "need" || op === "bad" || op.end > message.end) return { state: "bad", reason: "LDAP message has no operation" };
  const startTls = op.tag === 0x77 && hasStartTlsOid(buf.subarray(op.valueStart, op.end));
  const resultCode = op.tag === 0x78 ? firstEnumerated(buf.subarray(op.valueStart, op.end)) : undefined;
  return { state: "ok", end: message.end, messageId, op: op.tag, startTls, resultCode };
}

export function startTlsRequest(messageId = 1): Buffer {
  const oid = tlv(0x80, START_TLS_OID);
  return tlv(0x30, Buffer.concat([integer(messageId), tlv(0x77, oid)]));
}

export function extendedResult(messageId: number, resultCode: number): Buffer {
  const result = Buffer.concat([
    tlv(0x0a, Buffer.from([resultCode])),
    tlv(0x04, Buffer.alloc(0)),
    tlv(0x04, Buffer.alloc(0)),
  ]);
  return tlv(0x30, Buffer.concat([integer(messageId), tlv(0x78, result)]));
}

function hasStartTlsOid(body: Buffer): boolean {
  let offset = 0;
  while (offset < body.length) {
    const field = readTlv(body, offset);
    if (field === "need" || field === "bad") return false;
    if (field.tag === 0x80 && body.subarray(field.valueStart, field.end).equals(START_TLS_OID)) return true;
    offset = field.end;
  }
  return false;
}

function firstEnumerated(body: Buffer): number | undefined {
  const field = readTlv(body, 0);
  if (field === "need" || field === "bad" || field.tag !== 0x0a) return;
  return body[field.valueStart];
}

function readTlv(buf: Buffer, offset: number): Tlv | "need" | "bad" {
  if (offset >= buf.length) return "need";
  const tag = buf[offset];
  if (offset + 1 >= buf.length) return "need";
  const length = readLength(buf, offset + 1);
  if (length === "need") return "need";
  if (length === "bad") return "bad";
  const end = length.valueStart + length.value;
  if (end > buf.length) return "need";
  return { tag, valueStart: length.valueStart, end };
}

function readLength(buf: Buffer, offset: number): { value: number; valueStart: number } | "need" | "bad" {
  if (offset >= buf.length) return "need";
  const first = buf[offset];
  if ((first & 0x80) === 0) return { value: first, valueStart: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 3) return "bad";
  if (offset + 1 + count > buf.length) return "need";
  let value = 0;
  for (let i = 0; i < count; i++) value = (value << 8) | buf[offset + 1 + i];
  return { value, valueStart: offset + 1 + count };
}

function readInteger(buf: Buffer): number {
  let value = 0;
  for (const byte of buf) value = (value << 8) | byte;
  return value;
}

function integer(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    bytes.push(rest & 0xff);
    rest = rest >> 8;
  } while (rest > 0);
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0);
  bytes.reverse();
  return tlv(0x02, Buffer.from(bytes));
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
}

function lengthBytes(length: number): Buffer {
  if (length < 128) return Buffer.from([length]);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.push(rest & 0xff);
    rest = rest >> 8;
  }
  bytes.reverse();
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
