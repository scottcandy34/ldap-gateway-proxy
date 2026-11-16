export type Tlv = { tag: number; start: number; valueStart: number; end: number };

export function readTlv(buf: Buffer, offset: number): Tlv | "need" | "bad" {
  if (offset >= buf.length) return "need";
  const tag = buf[offset]!;
  if (offset + 1 >= buf.length) return "need";
  const length = readLength(buf, offset + 1);
  if (length === "need" || length === "bad") return length;
  const end = length.valueStart + length.value;
  if (end > buf.length) return "need";
  return { tag, start: offset, valueStart: length.valueStart, end };
}

export function readLength(buf: Buffer, offset: number): { value: number; valueStart: number } | "need" | "bad" {
  if (offset >= buf.length) return "need";
  const first = buf[offset]!;
  if ((first & 0x80) === 0) return { value: first, valueStart: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 4) return "bad";
  if (offset + 1 + count > buf.length) return "need";
  let value = 0;
  for (let i = 0; i < count; i++) value = (value << 8) | buf[offset + 1 + i]!;
  return { value, valueStart: offset + 1 + count };
}

export function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
}

export function integer(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    bytes.push(rest & 0xff);
    rest = rest >> 8;
  } while (rest > 0);
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  bytes.reverse();
  return tlv(0x02, Buffer.from(bytes));
}

export function octet(value: string | Buffer): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value) : value;
  return tlv(0x04, bytes);
}

export function readInteger(buf: Buffer): number {
  let value = 0;
  for (const byte of buf) value = (value << 8) | byte;
  return value;
}

export function readString(buf: Buffer, field: Tlv): string {
  return buf.toString("utf8", field.valueStart, field.end);
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
