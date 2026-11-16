import { readString, readTlv, tlv, octet, type Tlv } from "./ber.js";

/** Canonical LDAP filter string. Attribute types are lowercased and values are escaped. */
export function canonicalFilter(input: string): string {
  let index = 0;
  const text = parseFilter(input, () => index, (next) => {
    index = next;
  });
  if (index !== input.length) throw new Error(`filter has trailing text: ${input.slice(index)}`);
  return text;
}

export function filterFromBer(buf: Buffer, offset: number): { text: string; end: number } {
  const field = readTlv(buf, offset);
  if (field === "need" || field === "bad") throw new Error("truncated LDAP filter");
  return { text: renderFilter(buf, field), end: field.end };
}

export function filterToBer(filter: string): Buffer {
  return encodeFilter(canonicalFilter(filter));
}

function parseFilter(input: string, get: () => number, set: (next: number) => void): string {
  if (input[get()] !== "(") throw new Error("LDAP filter must be wrapped in parentheses");
  set(get() + 1);
  const body = parseComp(input, get, set);
  if (input[get()] !== ")") throw new Error("LDAP filter is missing ')'");
  set(get() + 1);
  return `(${body})`;
}

function parseComp(input: string, get: () => number, set: (next: number) => void): string {
  const mark = input[get()];
  if (mark === "&" || mark === "|") {
    set(get() + 1);
    const parts: string[] = [];
    while (input[get()] === "(") parts.push(parseFilter(input, get, set));
    if (parts.length === 0) throw new Error("LDAP filter combination is empty");
    return `${mark}${parts.join("")}`;
  }
  if (mark === "!") {
    set(get() + 1);
    return `!${parseFilter(input, get, set)}`;
  }
  return parseItem(input, get, set);
}

function parseItem(input: string, get: () => number, set: (next: number) => void): string {
  const start = get();
  while (get() < input.length && !"=~<>)".includes(input[get()]!)) set(get() + 1);
  const attribute = input.slice(start, get()).trim().toLowerCase();
  if (!attribute) throw new Error("LDAP filter is missing an attribute");
  let operator = "";
  if (input.startsWith("~=", get()) || input.startsWith(">=", get()) || input.startsWith("<=", get())) {
    operator = input.slice(get(), get() + 2);
    set(get() + 2);
  } else if (input[get()] === "=") {
    operator = "=";
    set(get() + 1);
  } else if (input[get()] === ":") {
    const ruleEnd = input.indexOf(":=", get());
    if (ruleEnd < 0) throw new Error("extensible LDAP filter is missing ':='");
    operator = input.slice(get(), ruleEnd + 2).toLowerCase();
    set(ruleEnd + 2);
  } else {
    throw new Error(`unsupported LDAP filter near ${input.slice(get())}`);
  }
  const raw = readAssertion(input, get, set);
  if (operator === "=" && raw.present) return `${attribute}=*`;
  if (operator === "=" && raw.pieces) return `${attribute}=${raw.pieces.map(escapeValue).join("*")}`;
  return `${attribute}${operator}${escapeValue(raw.value)}`;
}

function readAssertion(input: string, get: () => number, set: (next: number) => void): { value: string; present: boolean; pieces?: string[] } {
  let value = "";
  const pieces: string[] = [];
  let sawStar = false;
  while (get() < input.length && input[get()] !== ")") {
    const char = input[get()]!;
    if (char === "\\") {
      const hex = input.slice(get() + 1, get() + 3);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        value += String.fromCharCode(Number.parseInt(hex, 16));
        set(get() + 3);
        continue;
      }
      value += input[get() + 1] ?? "";
      set(get() + 2);
      continue;
    }
    if (char === "*") {
      sawStar = true;
      pieces.push(value);
      value = "";
      set(get() + 1);
      continue;
    }
    value += char;
    set(get() + 1);
  }
  if (!sawStar) return { value, present: false };
  pieces.push(value);
  return { value: "", present: pieces.length === 2 && pieces[0] === "" && pieces[1] === "", pieces };
}

function renderFilter(buf: Buffer, field: Tlv): string {
  const body = buf.subarray(field.valueStart, field.end);
  if (field.tag === 0xa0 || field.tag === 0xa1) {
    const mark = field.tag === 0xa0 ? "&" : "|";
    const parts: string[] = [];
    let offset = 0;
    while (offset < body.length) {
      const next = filterFromBer(body, offset);
      parts.push(next.text);
      offset = next.end;
    }
    return `(${mark}${parts.join("")})`;
  }
  if (field.tag === 0xa2) {
    const inner = filterFromBer(body, 0);
    return `(!${inner.text})`;
  }
  if (field.tag === 0x87) return `(${body.toString("utf8").toLowerCase()}=*)`;
  const [attribute, value] = pair(buf, field);
  if (field.tag === 0xa3) return `(${attribute}=${escapeValue(value)})`;
  if (field.tag === 0xa5) return `(${attribute}>=${escapeValue(value)})`;
  if (field.tag === 0xa6) return `(${attribute}<=${escapeValue(value)})`;
  if (field.tag === 0xa8) return `(${attribute}~=${escapeValue(value)})`;
  if (field.tag === 0xa4) return `(${attribute}=${substrings(buf, field)})`;
  if (field.tag === 0xa9) return extensible(buf, field);
  throw new Error(`unsupported LDAP filter tag 0x${field.tag.toString(16)}`);
}

function pair(buf: Buffer, field: Tlv): [string, string] {
  const attribute = readTlv(buf, field.valueStart);
  if (attribute === "need" || attribute === "bad") throw new Error("bad LDAP filter attribute");
  const value = readTlv(buf, attribute.end);
  if (value === "need" || value === "bad") throw new Error("bad LDAP filter value");
  return [readString(buf, attribute).toLowerCase(), readString(buf, value)];
}

function substrings(buf: Buffer, field: Tlv): string {
  const attribute = readTlv(buf, field.valueStart);
  if (attribute === "need" || attribute === "bad") throw new Error("bad substring filter");
  const list = readTlv(buf, attribute.end);
  if (list === "need" || list === "bad") throw new Error("bad substring list");
  const parts = ["", "", ""];
  const any: string[] = [];
  let offset = list.valueStart;
  while (offset < list.end) {
    const piece = readTlv(buf, offset);
    if (piece === "need" || piece === "bad") throw new Error("bad substring piece");
    const text = escapeValue(readString(buf, piece));
    if (piece.tag === 0x80) parts[0] = text;
    else if (piece.tag === 0x81) any.push(text);
    else if (piece.tag === 0x82) parts[2] = text;
    offset = piece.end;
  }
  const initial = parts[0] ?? "";
  const final = parts[2] ?? "";
  const bits = [initial];
  bits.push(...any);
  if (final || any.length > 0 || initial) bits.push(final);
  return bits.join("*");
}

function extensible(buf: Buffer, field: Tlv): string {
  let attribute = "";
  let rule = "";
  let value = "";
  let dn = false;
  let offset = field.valueStart;
  while (offset < field.end) {
    const piece = readTlv(buf, offset);
    if (piece === "need" || piece === "bad") throw new Error("bad extensible filter");
    if (piece.tag === 0x81) rule = readString(buf, piece).toLowerCase();
    else if (piece.tag === 0x82) attribute = readString(buf, piece).toLowerCase();
    else if (piece.tag === 0x83) value = readString(buf, piece);
    else if (piece.tag === 0x84) dn = buf[piece.valueStart] !== 0;
    offset = piece.end;
  }
  const dnMark = dn ? ":dn" : "";
  const ruleMark = rule ? `:${rule}` : "";
  return `(${attribute}${dnMark}${ruleMark}:=${escapeValue(value)})`;
}

function encodeFilter(filter: string): Buffer {
  const body = filter.slice(1, -1);
  if (body.startsWith("&") || body.startsWith("|")) {
    const tag = body.startsWith("&") ? 0xa0 : 0xa1;
    const nested = splitFilters(body.slice(1));
    return tlv(tag, Buffer.concat(nested.map(encodeFilter)));
  }
  if (body.startsWith("!")) return tlv(0xa2, encodeFilter(body.slice(1)));
  const present = /^([a-zA-Z][\w.-]*)=\*$/.exec(body);
  if (present) return tlv(0x87, Buffer.from(present[1]!.toLowerCase()));
  const simple = /^([a-zA-Z][\w.-]*)(=|~=|>=|<=)([\s\S]*)$/.exec(body);
  if (!simple) throw new Error(`cannot encode filter (${filter})`);
  const attribute = simple[1]!.toLowerCase();
  const operator = simple[2]!;
  const raw = unescapeValue(simple[3]!);
  if (operator === "=" && raw.includes("*")) return encodeSubstring(attribute, raw);
  const tag = operator === "=" ? 0xa3 : operator === ">=" ? 0xa5 : operator === "<=" ? 0xa6 : 0xa8;
  return tlv(tag, Buffer.concat([octet(attribute), octet(raw)]));
}

function encodeSubstring(attribute: string, value: string): Buffer {
  const pieces = value.split("*");
  const encoded: Buffer[] = [];
  pieces.forEach((piece, index) => {
    if (!piece) return;
    const tag = index === 0 ? 0x80 : index === pieces.length - 1 ? 0x82 : 0x81;
    encoded.push(tlv(tag, Buffer.from(unescapeValue(piece))));
  });
  return tlv(0xa4, Buffer.concat([octet(attribute), tlv(0x30, Buffer.concat(encoded))]));
}

function splitFilters(input: string): string[] {
  const filters: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < input.length; i++) {
    if (input[i] === "(") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (input[i] === ")") {
      depth -= 1;
      if (depth === 0) filters.push(input.slice(start, i + 1));
    }
  }
  return filters;
}

function escapeValue(value: string): string {
  return value.replace(/[\\*()\0]/g, (char) => `\\${char.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

function unescapeValue(value: string): string {
  return value.replace(/\\([0-9a-fA-F]{2})/g, (_match, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}
