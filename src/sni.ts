/** Enough of a TLS ClientHello to recover the SNI, without decrypting anything. */

export type HelloView =
  | { state: "need" }
  | { state: "ok"; end: number; sni?: string }
  | { state: "bad"; reason: string };

export function inspectClientHello(buf: Buffer): HelloView {
  if (buf.length < 1) return { state: "need" };
  if (buf[0] !== 22) return { state: "bad", reason: "not a TLS handshake" };
  let offset = 0;
  let hello: Buffer | undefined;
  let helloNeed = 0;
  let helloGot = 0;

  while (offset < buf.length || helloGot < helloNeed) {
    if (buf.length - offset < 5) return hello ? { state: "need" } : offset === 0 ? { state: "need" } : { state: "bad", reason: "truncated TLS record" };
    const contentType = buf[offset];
    const recordLen = buf.readUInt16BE(offset + 3);
    if (recordLen === 0 || recordLen > 16384) return { state: "bad", reason: "invalid TLS record" };
    if (buf.length - offset < 5 + recordLen) return { state: "need" };
    const fragment = buf.subarray(offset + 5, offset + 5 + recordLen);
    offset += 5 + recordLen;
    if (contentType !== 22) {
      if (!hello) return { state: "bad", reason: "not a TLS handshake" };
      break;
    }
    let at = 0;
    while (at < fragment.length) {
      if (!hello) {
        if (fragment.length - at < 4) return { state: "bad", reason: "truncated handshake header" };
        if (fragment[at] !== 1) return { state: "bad", reason: "not a ClientHello" };
        helloNeed = (fragment[at + 1] << 16) | (fragment[at + 2] << 8) | fragment[at + 3];
        if (helloNeed < 40 || helloNeed > 65536) return { state: "bad", reason: "invalid ClientHello length" };
        hello = Buffer.alloc(helloNeed);
        at += 4;
      }
      const take = Math.min(helloNeed - helloGot, fragment.length - at);
      fragment.copy(hello, helloGot, at, at + take);
      helloGot += take;
      at += take;
      if (helloGot === helloNeed) {
        return { state: "ok", end: offset, sni: serverName(hello) };
      }
    }
  }
  return { state: "need" };
}

function serverName(hello: Buffer): string | undefined {
  let offset = 34; // legacy_version (2) + random (32)
  if (hello.length < offset + 1) return;
  const sessionLen = hello[offset];
  offset += 1 + sessionLen;
  if (hello.length < offset + 2) return;
  const cipherLen = hello.readUInt16BE(offset);
  offset += 2 + cipherLen;
  if (hello.length < offset + 1) return;
  const compressionLen = hello[offset];
  offset += 1 + compressionLen;
  if (hello.length < offset + 2) return;
  const extensionsLen = hello.readUInt16BE(offset);
  offset += 2;
  const end = Math.min(hello.length, offset + extensionsLen);
  while (offset + 4 <= end) {
    const type = hello.readUInt16BE(offset);
    const length = hello.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + length > end) return;
    if (type === 0) return hostName(hello.subarray(offset, offset + length));
    offset += length;
  }
  return;
}

function hostName(extension: Buffer): string | undefined {
  if (extension.length < 2) return;
  const listLen = extension.readUInt16BE(0);
  let offset = 2;
  const end = Math.min(extension.length, offset + listLen);
  while (offset + 3 <= end) {
    const nameType = extension[offset];
    const nameLen = extension.readUInt16BE(offset + 1);
    offset += 3;
    if (offset + nameLen > end) return;
    if (nameType === 0) return extension.toString("utf8", offset, offset + nameLen);
    offset += nameLen;
  }
  return;
}
