/**
 * FIFA 17 Ultimate Team Private Server - Standalone
 * Run with: node server.mjs
 * 
 * Implements a minimal SSLv3 handshake for the Blaze redirector since
 * EA's game client uses a custom "ProtoSSL" that only supports SSLv3
 * with TLS_RSA_WITH_RC4_128_SHA cipher suite.
 */

import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

// Auto-logging: capture console output and push after each disconnect
let sessionLog = [];
const origLog = console.log;
console.log = function(...args) {
  const msg = args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
  sessionLog.push(msg);
  origLog.apply(console, args);
};

function flushAndPush(label) {
  try {
    const logPath = path.join(repoRoot, 'batch-results.log');
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const last200 = sessionLog.slice(-200).join('\n');
    const content = `=== ${label} (${timestamp}) ===\n\n${last200}\n`;
    fs.appendFileSync(logPath, content, 'utf8');
    sessionLog = [];
    origLog('[LOG] Saved: ' + label);
  } catch (e) {
    origLog('[LOG] Error: ' + e.message);
    sessionLog = [];
  }
}

const REDIRECTOR_PORT = 42230;
const MAIN_BLAZE_PORT = 10041;
const HTTP_PORT = 8080;
const TARGET_HOST = '127.0.0.1';

// ============================================================
// TDF Encoder (EA's binary serialization format)
// ============================================================

class TdfEncoder {
  constructor() { this.buffers = []; }

  encodeTag(tag) {
    if (tag.length !== 4) throw new Error(`Tag must be 4 chars: "${tag}"`);
    const buf = Buffer.alloc(3);
    const c0 = tag.charCodeAt(0) - 0x20;
    const c1 = tag.charCodeAt(1) - 0x20;
    const c2 = tag.charCodeAt(2) - 0x20;
    const c3 = tag.charCodeAt(3) - 0x20;
    buf[0] = (c0 << 2) | ((c1 >> 4) & 0x03);
    buf[1] = ((c1 & 0x0F) << 4) | ((c2 >> 2) & 0x0F);
    buf[2] = ((c2 & 0x03) << 6) | (c3 & 0x3F);
    return buf;
  }

  writeTagAndType(tag, type) {
    this.buffers.push(this.encodeTag(tag));
    this.buffers.push(Buffer.from([type]));
  }

  encodeVarInt(value) {
    let v = BigInt(value);
    const bytes = [];
    // First byte: 6 data bits, bit 7 = continuation (matches EA's BlazeSDK format)
    if (v < 0n) { v = -v; bytes.push(Number(v & 0x3Fn) | 0x80); v >>= 6n; }
    else { bytes.push(Number(v & 0x3Fn)); v >>= 6n; }
    // Set continuation bit on previous byte and add next byte
    while (v > 0n) { 
      bytes[bytes.length - 1] |= 0x80; // continuation bit 7 on ALL bytes
      bytes.push(Number(v & 0x7Fn)); 
      v >>= 7n; 
    }
    return Buffer.from(bytes);
  }

  writeInteger(tag, value) { this.writeTagAndType(tag, 0x00); this.buffers.push(this.encodeVarInt(value)); return this; }
  writeString(tag, value) { this.writeTagAndType(tag, 0x01); const s = Buffer.from(value + '\0', 'utf-8'); this.buffers.push(this.encodeVarInt(s.length)); this.buffers.push(s); return this; }
  writeBlob(tag, data) { this.writeTagAndType(tag, 0x02); this.buffers.push(this.encodeVarInt(data.length)); this.buffers.push(data); return this; }
  writeStructStart(tag) { this.writeTagAndType(tag, 0x03); return this; }
  writeStructEnd() { this.buffers.push(Buffer.from([0x00])); return this; }
  writeUnion(tag, type, cb) { this.writeTagAndType(tag, 0x06); this.buffers.push(Buffer.from([type])); if (type !== 0x7F) cb(this); return this; }
  writeIntList(tag, vals) { this.writeTagAndType(tag, 0x07); this.buffers.push(this.encodeVarInt(vals.length)); for (const v of vals) this.buffers.push(this.encodeVarInt(v)); return this; }
  writeList(tag, itemType, count, cb) { this.writeTagAndType(tag, 0x04); this.buffers.push(Buffer.from([itemType])); this.buffers.push(this.encodeVarInt(count)); for (let i = 0; i < count; i++) { cb(this, i); if (itemType === 0x03) this.buffers.push(Buffer.from([0x00])); } return this; }
  writeIntegerList(tag, vals) {
    // Proper List<int>: type 0x04 (LIST), itemType 0x00 (INTEGER), count, VarInts
    this.writeTagAndType(tag, 0x04);
    this.buffers.push(Buffer.from([0x00])); // itemType = integer
    this.buffers.push(this.encodeVarInt(vals.length));
    for (const v of vals) this.buffers.push(this.encodeVarInt(v));
    return this;
  }
  writeMap(tag, map) {
    // TDF Map: type 0x05, keyType(1), valueType(1), count(varint), then key-value pairs
    this.writeTagAndType(tag, 0x05);
    const entries = Object.entries(map);
    this.buffers.push(Buffer.from([0x01, 0x01])); // keyType=string, valueType=string
    this.buffers.push(this.encodeVarInt(entries.length));
    for (const [k, v] of entries) {
      const kBuf = Buffer.from(k + '\0', 'utf-8');
      this.buffers.push(this.encodeVarInt(kBuf.length));
      this.buffers.push(kBuf);
      const vBuf = Buffer.from(v + '\0', 'utf-8');
      this.buffers.push(this.encodeVarInt(vBuf.length));
      this.buffers.push(vBuf);
    }
    return this;
  }
  build() { return Buffer.concat(this.buffers); }
}

// TDF Decoder - decode TDF binary to readable format
function decodeTdf(buf, depth = 0) {
  const result = [];
  let offset = 0;
  const indent = '  '.repeat(depth);
  
  while (offset < buf.length) {
    if (buf[offset] === 0x00) { offset++; break; } // struct end
    if (offset + 4 > buf.length) break;
    
    // Decode tag (3 bytes)
    const b0 = buf[offset], b1 = buf[offset+1], b2 = buf[offset+2];
    const c0 = String.fromCharCode((b0 >> 2) + 0x20);
    const c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
    const c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
    const c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
    const tag = c0 + c1 + c2 + c3;
    const type = buf[offset + 3];
    offset += 4;
    
    try {
      if (type === 0x00) { // Integer
        const vr = decodeVarInt(buf, offset);
        offset = vr.newOffset;
        result.push(`${indent}${tag} (int) = ${vr.value}`);
      } else if (type === 0x01) { // String
        const lenResult = decodeVarInt(buf, offset);
        offset = lenResult.newOffset;
        const len = Number(lenResult.value);
        const str = buf.toString('utf-8', offset, offset + len - 1); // -1 for null terminator
        offset += len;
        result.push(`${indent}${tag} (str) = "${str}"`);
      } else if (type === 0x02) { // Blob
        const lenResult = decodeVarInt(buf, offset);
        offset = lenResult.newOffset;
        offset += Number(lenResult.value);
        result.push(`${indent}${tag} (blob) [${lenResult.value} bytes]`);
      } else if (type === 0x03) { // Struct
        result.push(`${indent}${tag} (struct) {`);
        const sub = decodeTdf(buf.subarray(offset), depth + 1);
        result.push(...sub.lines);
        offset += sub.consumed;
        result.push(`${indent}}`);
      } else if (type === 0x04) { // List
        const itemType = buf[offset++];
        const countResult = decodeVarInt(buf, offset);
        offset = countResult.newOffset;
        result.push(`${indent}${tag} (list) itemType=${itemType} count=${countResult.value}`);
        // Skip list items for now
        for (let i = 0; i < Number(countResult.value); i++) {
          if (itemType === 0x03) { // struct items
            const sub = decodeTdf(buf.subarray(offset), depth + 1);
            result.push(...sub.lines);
            offset += sub.consumed;
          }
        }
      } else if (type === 0x05) { // Map
        const keyType = buf[offset++];
        const valType = buf[offset++];
        const countResult = decodeVarInt(buf, offset);
        offset = countResult.newOffset;
        result.push(`${indent}${tag} (map) k=${keyType} v=${valType} count=${countResult.value}`);
      } else if (type === 0x06) { // Union
        const unionType = buf[offset++];
        result.push(`${indent}${tag} (union) type=${unionType}`);
        if (unionType !== 0x7F) {
          // Union contains one value - skip it for now
        }
      } else if (type === 0x07) { // IntList  
        const countResult = decodeVarInt(buf, offset);
        offset = countResult.newOffset;
        const vals = [];
        for (let i = 0; i < Number(countResult.value); i++) {
          const vr = decodeVarInt(buf, offset);
          offset = vr.newOffset;
          vals.push(vr.value.toString());
        }
        result.push(`${indent}${tag} (intlist) = [${vals.join(', ')}]`);
      } else if (type === 0x08) { // Pair/ObjectType
        const vr1 = decodeVarInt(buf, offset);
        offset = vr1.newOffset;
        const vr2 = decodeVarInt(buf, offset);
        offset = vr2.newOffset;
        result.push(`${indent}${tag} (pair) = (${vr1.value}, ${vr2.value})`);
      } else if (type === 0x09) { // Triple
        const vr1 = decodeVarInt(buf, offset);
        offset = vr1.newOffset;
        const vr2 = decodeVarInt(buf, offset);
        offset = vr2.newOffset;
        const vr3 = decodeVarInt(buf, offset);
        offset = vr3.newOffset;
        result.push(`${indent}${tag} (triple) = (${vr1.value}, ${vr2.value}, ${vr3.value})`);
      } else if (type === 0x0C) { // Float/VarList
        const vr = decodeVarInt(buf, offset);
        offset = vr.newOffset;
        result.push(`${indent}${tag} (type0C) = ${vr.value}`);
      } else {
        result.push(`${indent}${tag} (type=0x${type.toString(16)}) ???`);
        break;
      }
    } catch (e) {
      result.push(`${indent}${tag} (type=0x${type.toString(16)}) DECODE ERROR: ${e.message}`);
      break;
    }
  }
  return { lines: result, consumed: offset };
}

function decodeVarInt(buf, offset) {
  let value = BigInt(buf[offset] & 0x3F);
  let hasMore = (buf[offset] & 0x80) !== 0;
  offset++;
  let shift = 6n;
  while (hasMore && offset < buf.length) {
    value |= BigInt(buf[offset] & 0x7F) << shift;
    hasMore = (buf[offset] & 0x80) !== 0;
    offset++;
    shift += 7n;
  }
  return { value, newOffset: offset };
}

// ============================================================
// Blaze Packet Codec
// ============================================================

// ============================================================
// Blaze Packet Header — FIFA 17 Fire2 Format (16 bytes)  
// ============================================================
// [0-3]   u32  payload length
// [4-5]   u16  secondary length (usually 0)
// [6-7]   u16  component
// [8-9]   u16  command
// [10-11] u16  error code
// [12]    u8   sequence number
// [13]    u8   flags/type
// [14-15] u16  extended id (usually 0)

const HEADER_SIZE = 16;

// CONFIRMED WORKING: byte12=echo seq, byte13=0x20 (notify type)
// Sweep test: press #3 = echo+0x20 produced "log in to Origin" message
// This means the game processes PreAuth response as a notification
const SWEEP_VALUES = [
  ['echo', 0x20, 'CONFIRMED: echo+0x20 (notify type)'],
];
let sweepIndex = 0;

function decodeHeader(buf) {
  if (buf.length < HEADER_SIZE) return null;
  const length = buf.readUInt32BE(0);
  const component = buf.readUInt16BE(6);
  const command = buf.readUInt16BE(8);
  // Fire2 header: [10-12] = u24 message ID, [13] = type/flags, [14-15] = error code
  const msgId = (buf[10] << 16) | (buf[11] << 8) | buf[12];
  const typeByte = buf[13];
  const msgType = (typeByte >> 5) & 0x07;  // top 3 bits = message type
  const flags = typeByte & 0x1F;            // bottom 5 bits = flags
  const error = buf.readUInt16BE(14);
  return { length, component, command, error, msgType, msgId, typeByte, flags };
}

function encodeHeader(h) {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt32BE(h.length || 0, 0);
  buf.writeUInt16BE(0, 4);                          // extended length
  buf.writeUInt16BE(h.component, 6);
  buf.writeUInt16BE(h.command, 8);
  // Fire2 header: [10-12] = u24 message ID, [13] = type/flags, [14-15] = error code
  const msgId = h.msgId || 0;
  buf[10] = (msgId >> 16) & 0xFF;
  buf[11] = (msgId >> 8) & 0xFF;
  buf[12] = msgId & 0xFF;
  if (h.notify) {
    // Notification: type=2 (010), flags=0 → byte13=0x40, msgId=0
    buf[10] = 0x00; buf[11] = 0x00; buf[12] = 0x00;
    buf[13] = 0x40;
  } else if ((h.error || 0) !== 0) {
    // Error response: type=3 (011), flags=0 → byte13=0x60
    buf[13] = 0x60;
  } else {
    // Response: type=1 (001), flags=0 → byte13=0x20
    buf[13] = 0x20;
  }
  buf.writeUInt16BE(h.error || 0, 14);
  return buf;
}
function readPacket(buf) {
  if (buf.length < HEADER_SIZE) return null;
  const header = decodeHeader(buf);
  if (!header) return null;
  const total = HEADER_SIZE + header.length;
  if (buf.length < total) return null;
  return { packet: { header, body: buf.subarray(HEADER_SIZE, total) }, remaining: buf.subarray(total) };
}
function buildReply(req, body, error = 0) {
  const h = encodeHeader({ 
    length: body.length, 
    component: req.header.component, 
    command: req.header.command, 
    error, 
    msgId: req.header.msgId   // echo the request's 3-byte message ID for RPC matching
  });
  return Buffer.concat([h, body]);
}
function ipToInt(ip) { const p = ip.split('.'); if (p.length !== 4) return 0; return p.reduce((a, o) => (a << 8) | parseInt(o), 0) >>> 0; }

// SSL/TLS helpers
function uint24(n) { return Buffer.from([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]); }
function wrapHandshake(type, body) { return Buffer.concat([Buffer.from([type]), uint24(body.length), body]); }
function wrapRecord(type, version, body) { return Buffer.concat([Buffer.from([type, version[0], version[1], (body.length >> 8) & 0xFF, body.length & 0xFF]), body]); }

function handleBlazeStream(socket, label, onPacket) {
  let buffer = Buffer.alloc(0);
  socket.on('data', (data) => {
    buffer = Buffer.concat([buffer, data]);
    let result = readPacket(buffer);
    while (result) { buffer = result.remaining; onPacket(result.packet); result = readPacket(buffer); }
  });
}

// ============================================================
// Minimal SSLv3 Server for EA's ProtoSSL
// ============================================================

/**
 * EA's ProtoSSL uses SSLv3 with TLS_RSA_WITH_RC4_128_SHA (0x0005).
 * Since Node.js dropped SSLv3 support, we implement the handshake manually.
 * 
 * The approach: accept the raw TCP connection, parse the SSLv3 ClientHello,
 * respond with ServerHello + Certificate + ServerHelloDone, receive the
 * ClientKeyExchange, then switch to RC4 encrypted communication.
 * 
 * However, implementing full SSLv3 crypto is complex. A simpler approach
 * that PocketRelay uses on the CLIENT side: run a local TCP proxy that
 * the game connects to via SSL, and the proxy forwards plain TCP to our server.
 * 
 * For now, let's try the simplest possible approach: use Node.js TLS with
 * legacy OpenSSL options enabled via command-line flags.
 */

// Try to enable legacy SSL support via OpenSSL provider
// Node.js 20 uses OpenSSL 3.x which requires explicit legacy provider

function startRedirector() {
  // Use raw TCP with manual TLS handshake on port 42230
  startRawRedirector();
}

// Raw TCP redirector that logs exactly what the game sends
function startRawRedirector() {
  const server = net.createServer((socket) => {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[Redirector-Raw] Client connected: ${addr}`);
    let allData = Buffer.alloc(0);

    socket.on('data', (data) => {
      allData = Buffer.concat([allData, data]);
      console.log(`[Redirector-Raw] Received ${data.length} bytes`);
      console.log(`[Redirector-Raw] Full hex dump:`);
      
      // Pretty print hex dump
      for (let i = 0; i < data.length; i += 16) {
        const slice = data.subarray(i, Math.min(i + 16, data.length));
        const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(slice).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
        console.log(`  ${i.toString(16).padStart(4, '0')}: ${hex.padEnd(48)} ${ascii}`);
      }

      // Check if this is an SSLv3 ClientHello
      if (data[0] === 0x16 && data[1] === 0x03 && data[2] === 0x00) {
        console.log('[Redirector-Raw] Detected SSLv3 ClientHello!');
        console.log('[Redirector-Raw] Attempting SSLv3 handshake...');
        handleSSLv3Handshake(socket, data);
      }
      // Check if this is a plaintext Blaze packet (no TLS wrapper)
      // Blaze packets have a 12-byte header. The component field at offset 2-3
      // for redirector is 0x0005, and command at offset 4-5 is 0x0001.
      else if (allData.length >= HEADER_SIZE) {
        const header = decodeHeader(allData);
        if (header && header.component === 0x0005 && header.command === 0x0001) {
          console.log('[Redirector-Raw] Detected PLAINTEXT Blaze GetServerInstance!');
          setupRedirectorHandler(socket);
          // Re-emit the data so the handler processes it
          socket.emit('data', allData);
        } else if (header) {
          console.log(`[Redirector-Raw] Plaintext Blaze: comp=0x${header.component.toString(16)} cmd=0x${header.command.toString(16)}`);
          setupRedirectorHandler(socket);
          socket.emit('data', allData);
        }
      }
    });

    socket.on('close', () => console.log(`[Redirector-Raw] Disconnected: ${addr}`));
    socket.on('error', (e) => console.log(`[Redirector-Raw] Error: ${e.message}`));
  });

  server.listen(REDIRECTOR_PORT, '0.0.0.0', () => {
    console.log(`[Redirector-Raw] Listening on port ${REDIRECTOR_PORT}`);
  });
}

/**
 * Minimal SSLv3 handshake handler.
 * 
 * SSLv3 handshake flow:
 * Client -> Server: ClientHello
 * Server -> Client: ServerHello, Certificate, ServerHelloDone
 * Client -> Server: ClientKeyExchange, ChangeCipherSpec, Finished
 * Server -> Client: ChangeCipherSpec, Finished
 * 
 * After handshake, data is encrypted with RC4-128-SHA
 */
function handleSSLv3Handshake(socket, clientHelloRecord) {
  const hsStart = 5;
  const hsType = clientHelloRecord[hsStart];
  if (hsType !== 0x01) { console.log(`[SSL] Not ClientHello (type=${hsType})`); socket.end(); return; }

  // Parse ClientHello
  const clientVersion = (clientHelloRecord[hsStart + 4] << 8) | clientHelloRecord[hsStart + 5];
  const clientRandom = Buffer.from(clientHelloRecord.subarray(hsStart + 6, hsStart + 6 + 32));
  // Use SSLv3 (0x0300) to match what the game's record layer uses
  // and what blaze-ssl-async uses. Previous versions used 0x0303 (TLS 1.2)
  // which may have been causing the rejection.
  const recordVersion = [0x03, 0x03]; // TLS 1.2 record layer (match ServerHello)
  const replyVersion = [0x03, 0x03]; // TLS 1.2 in ServerHello body

  console.log(`[SSL] ClientHello: version=0x${clientVersion.toString(16)} random=${clientRandom.toString('hex').substring(0, 16)}...`);

  const sidLen = clientHelloRecord[hsStart + 6 + 32];
  const sidEnd = hsStart + 6 + 32 + 1 + sidLen;
  const csLen = (clientHelloRecord[sidEnd] << 8) | clientHelloRecord[sidEnd + 1];
  const cipherSuites = [];
  for (let i = 0; i < csLen; i += 2) cipherSuites.push((clientHelloRecord[sidEnd + 2 + i] << 8) | clientHelloRecord[sidEnd + 2 + i + 1]);
  console.log(`[SSL] Ciphers: ${cipherSuites.map(c => '0x' + c.toString(16).padStart(4, '0')).join(', ')}`);

  // Pick cipher - use RC4-128-SHA (0x0005) which is what blaze-ssl-async uses
  // and what SSLv3 ProtoSSL expects. Previous versions used AES-256-CBC which
  // may not be supported by ProtoSSL's SSLv3 implementation.
  let selectedCipher = 0x0005; // TLS_RSA_WITH_RC4_128_SHA
  if (!cipherSuites.includes(0x0005)) {
    if (cipherSuites.includes(0x0004)) selectedCipher = 0x0004; // RC4-MD5
    else selectedCipher = cipherSuites[0];
  }
  console.log(`[SSL] Selected cipher: 0x${selectedCipher.toString(16).padStart(4, '0')}`);

  // Generate server random
  const serverRandom = crypto.randomBytes(32);
  serverRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);

  // Server cert signed by our CA (SHA1withRSA, proper signature)
  // The DLL replaces the CA's RSA modulus in memory with our CA's modulus,
  // so the game will verify this cert against our CA key and it'll pass.
  const certDerB64 = 'MIICrTCCAhYCFEPuJkoJqIs+1Hc7CaSyYdNeUYDTMA0GCSqGSIb3DQEBBQUAMIGgMSAwHgYDVQQLDBdPbmxpbmUgVGVjaG5vbG9neSBHcm91cDEeMBwGA1UECgwVRWxlY3Ryb25pYyBBcnRzLCBJbmMuMRUwEwYDVQQHDAxSZWR3b29kIENpdHkxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMSMwIQYDVQQDDBpPVEczIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0yNjA0MTAxMjUzNTVaFw01MzA4MjYxMjUzNTVaMIGJMSYwJAYDVQQDDB13aW50ZXIxNS5nb3NyZWRpcmVjdG9yLmVhLmNvbTEdMBsGA1UECwwUR2xvYmFsIE9ubGluZSBTdHVkaW8xHjAcBgNVBAoMFUVsZWN0cm9uaWMgQXJ0cywgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK4Jk1ombSA0y8N7G5RO4GyclW4dEp6E3GwvS2kKnyLgSHarNqj6qY4f06sX+U+4i6Uqz7ukxFFAyormGJKDZxPMCAYO48lHTsbGhvRIimCePpqxMTGOxbBw63TvZfOWdFGNJwSnA8Hzqu8FmEW3qAwX9ZjUCrTaFowYC60L09V3AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAE4v8rraydetF9oMcQ403Pm3Dz2k/ZXklQtt3pz3o/Hx1GH8kFIdMMoucCiQTyxOF97K32x96LI+CKzYgX15WehvtNGZUALHFdBpYTFIEVbnOijBsHqcKS3bn6P75znZTgRRzJJO4GV0cDKa6DZyPJraz7wvPD92RVplAgrWiUPw=';
  const certDerBuf = Buffer.from(certDerB64, 'base64');
  
  const keyPem = `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK4Jk1ombSA0y8N7
G5RO4GyclW4dEp6E3GwvS2kKnyLgSHarNqj6qY4f06sX+U+4i6Uqz7ukxFFAyorm
GJKDZxPMCAYO48lHTsbGhvRIimCePpqxMTGOxbBw63TvZfOWdFGNJwSnA8Hzqu8F
mEW3qAwX9ZjUCrTaFowYC60L09V3AgMBAAECgYAm9QHE9kELKoZKFa6Qvi9CYLKa
WWunjDoDBXst4jDJD8douN6daK63n6wz6kPmcnrf1/t0F2fSgFxWRzdM5JkX2Nq6
seZt5AF27wkIcWrBczj6zx4j3BSVR+0QOf6yaF0RTH4JFcQ7l4ToxP6QU37Te3NN
Dh/2cHavIqn2EJVMcQJBANbtZmcBDGsu8MPhp5dm3CuKAIf3Us+bDweDCftvB47f
8b5w/in35WuVy9GL5QmA33FIpSFhHUpBV3VOA8YKVBUCQQDPS8W40/pq/G4H84Wt
fPQzs436lOARszW7mBcRKSNCd41BpvSWbm77LYdEQQ4sRAVHGkDoxsJyq7cSnWZb
iqpbAkAk+Db6FtMVCMD/YKxcPaQ3lQhcWu2SqmBecWrhJgsNx3WkxXjirTJ4XA7w
H3kpNlK5AL7uy+6m3DB4DBBYG2S1AkANFrGzS98h5jJkWiH0pFEe+pVaXxAOzgv0
flPmh3xsc/P9UzdaUDq9rVA/JQRqExlqNeQnTnV0nBcBG+McoJLFAkEAjwGFmpsl
4QAR2AV6Lh3cWSlCgacyxgKTIJCLKFwmBiVZfdfeXmxvNfStU4ECeJ0hBcEfIs4a
bT9J4z1OJr6cTA==
-----END PRIVATE KEY-----`;

  // Session ID
  const sessionId = crypto.randomBytes(32);

  // === ServerHello ===
  const serverHelloBody = Buffer.concat([
    Buffer.from(replyVersion),   // Server version: SSLv3
    serverRandom,
    Buffer.from([32]), sessionId,
    Buffer.from([(selectedCipher >> 8) & 0xFF, selectedCipher & 0xFF]),
    Buffer.from([0x00]),         // compression: none
    // No extensions for SSLv3
  ]);
  const serverHelloMsg = wrapHandshake(0x02, serverHelloBody);

  // === Certificate (server cert with real cert data) ===
  const certBody = Buffer.concat([
    uint24(certDerBuf.length + 3),
    uint24(certDerBuf.length), certDerBuf,
  ]);
  const certMsg = wrapHandshake(0x0B, certBody);

  // === ServerHelloDone ===
  const helloDoneMsg = wrapHandshake(0x0E, Buffer.alloc(0));

  // Track all handshake messages for Finished verification
  const allHandshakeMessages = [
    clientHelloRecord.subarray(hsStart), // ClientHello handshake msg
    serverHelloMsg,
    certMsg,
    helloDoneMsg,
  ];

  // Set up the listener for client response BEFORE sending our messages
  let phase = 'waiting_client_response';
  let pendingBuf = Buffer.alloc(0);

  // Add a timeout to detect if the game sends nothing
  const clientTimeout = setTimeout(() => {
    console.log('[SSL] TIMEOUT: No data received from client after 10 seconds');
    console.log('[SSL] pendingBuf length:', pendingBuf.length);
    if (pendingBuf.length > 0) {
      console.log('[SSL] Pending data hex:');
      for (let i = 0; i < Math.min(pendingBuf.length, 128); i += 16) {
        const slice = pendingBuf.subarray(i, Math.min(i + 16, pendingBuf.length));
        console.log(`  ${i.toString(16).padStart(4, '0')}: ${Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
      }
    }
  }, 10000);

  // State machine for the handshake:
  // Phase 1: waiting_key_exchange - waiting for ClientKeyExchange
  // Phase 2: waiting_ccs - got keys, waiting for ChangeCipherSpec
  // Phase 3: waiting_client_finished - CCS received, RC4 initialized, waiting for encrypted Finished
  // Phase 4: established - handshake complete
  let gotCCS = false;

  socket.removeAllListeners('data');
  socket.on('data', (data) => {
    pendingBuf = Buffer.concat([pendingBuf, data]);
    console.log(`[SSL] Phase=${phase}, received ${data.length} bytes (total pending: ${pendingBuf.length})`);
    clearTimeout(clientTimeout);

    // Hex dump first 256 bytes
    for (let i = 0; i < Math.min(data.length, 256); i += 16) {
      const slice = data.subarray(i, Math.min(i + 16, data.length));
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
      console.log(`  ${i.toString(16).padStart(4, '0')}: ${hex}`);
    }

    if (phase === 'waiting_client_response') {
      // Parse TLS records from the client
      let offset = 0;
      while (offset + 5 <= pendingBuf.length) {
        const recType = pendingBuf[offset];
        const recVer = (pendingBuf[offset + 1] << 8) | pendingBuf[offset + 2];
        const recLen = (pendingBuf[offset + 3] << 8) | pendingBuf[offset + 4];
        
        if (offset + 5 + recLen > pendingBuf.length) break; // incomplete record
        
        const recBody = pendingBuf.subarray(offset + 5, offset + 5 + recLen);
        console.log(`[SSL] Record: type=0x${recType.toString(16)} ver=0x${recVer.toString(16)} len=${recLen}`);

        if (recType === 0x16 && !gotCCS) {
          // Plaintext handshake record (before CCS)
          const hsType = recBody[0];
          console.log(`[SSL] Handshake type: 0x${hsType.toString(16)} (${hsType === 0x10 ? 'ClientKeyExchange' : hsType === 0x14 ? 'Finished' : 'unknown'})`);
          
          if (hsType === 0x10) {
            // ClientKeyExchange - extract and decrypt pre-master secret
            const pmsBodyLen = (recBody[1] << 16) | (recBody[2] << 8) | recBody[3];
            let encPMS;
            if (pmsBodyLen > 128) {
              const explicitLen = (recBody[4] << 8) | recBody[5];
              encPMS = recBody.subarray(6, 6 + explicitLen);
              console.log(`[SSL] Encrypted PMS: ${encPMS.length} bytes (TLS format, explicit len: ${explicitLen})`);
            } else {
              encPMS = recBody.subarray(4, 4 + pmsBodyLen);
              console.log(`[SSL] Encrypted PMS: ${encPMS.length} bytes (SSLv3 format)`);
            }

            try {
              const preMasterSecret = crypto.privateDecrypt(
                { key: keyPem, padding: crypto.constants.RSA_PKCS1_PADDING, oaepHash: undefined },
                encPMS
              );
              console.log(`[SSL] Decrypted PMS: ${preMasterSecret.length} bytes, version=0x${preMasterSecret.readUInt16BE(0).toString(16)}`);

              const keys = deriveKeys(preMasterSecret, clientRandom, serverRandom, selectedCipher);
              console.log(`[SSL] Master secret derived: ${keys.masterSecret.toString('hex').substring(0, 32)}...`);

              socket._sslKeys = keys;
              socket._selectedCipher = selectedCipher;
              socket._allHS = allHandshakeMessages;
              socket._allHS.push(Buffer.from(recBody)); // add ClientKeyExchange (copy it)
              console.log(`[SSL] Keys stored. Waiting for ChangeCipherSpec + client Finished...`);
            } catch (e) {
              console.log(`[SSL] Failed to decrypt PMS: ${e.message}`);
              socket.end();
              return;
            }
          }
        } else if (recType === 0x14) {
          // ChangeCipherSpec (not a handshake message, not included in hash)
          console.log('[SSL] Client ChangeCipherSpec received - initializing RC4 decryption');
          gotCCS = true;
          
          if (socket._sslKeys) {
            // Initialize the client->server RC4 cipher for decrypting subsequent records
            const keys = socket._sslKeys;
            if (!keys._clientRC4) {
              keys._clientRC4 = crypto.createDecipheriv('rc4', keys.clientWriteKey, Buffer.alloc(0));
            }
            console.log(`[SSL] RC4 decryption initialized with clientWriteKey: ${keys.clientWriteKey.toString('hex')}`);
          }
        } else if (recType === 0x16 && gotCCS && socket._sslKeys) {
          // Encrypted handshake record AFTER CCS - this is the client's Finished
          console.log(`[SSL] Encrypted handshake record (client Finished): ${recLen} bytes`);
          
          const keys = socket._sslKeys;
          
          // Decrypt with RC4
          const decrypted = keys._clientRC4.update(recBody);
          console.log(`[SSL] Decrypted client Finished record: ${decrypted.length} bytes`);
          console.log(`[SSL] Decrypted hex: ${decrypted.toString('hex')}`);
          
          // Structure: handshake_message(16 bytes) + HMAC-SHA1(20 bytes) = 36 bytes
          // Handshake message: type(1) + length(3) + verify_data(12) = 16 bytes
          const clientFinishedPlaintext = decrypted.subarray(0, decrypted.length - 20);
          const clientFinishedMAC = decrypted.subarray(decrypted.length - 20);
          
          console.log(`[SSL] Client Finished plaintext (${clientFinishedPlaintext.length} bytes): ${clientFinishedPlaintext.toString('hex')}`);
          console.log(`[SSL] Client Finished MAC: ${clientFinishedMAC.toString('hex')}`);
          
          // Verify the client's Finished verify_data
          const allHSBeforeClientFinished = Buffer.concat(socket._allHS);
          const expectedClientVerify = tls12PRF(keys.masterSecret, 'client finished',
            crypto.createHash('sha256').update(allHSBeforeClientFinished).digest(), 12);
          const clientVerifyData = clientFinishedPlaintext.subarray(4); // skip type(1)+length(3)
          
          console.log(`[SSL] Client verify_data:   ${clientVerifyData.toString('hex')}`);
          console.log(`[SSL] Expected verify_data:  ${expectedClientVerify.toString('hex')}`);
          
          if (clientVerifyData.equals(expectedClientVerify)) {
            console.log('[SSL] ✓ Client Finished verify_data MATCHES!');
          } else {
            console.log('[SSL] ✗ Client Finished verify_data MISMATCH (continuing anyway)');
          }
          
          // Verify MAC on client Finished
          const seqBuf = Buffer.alloc(8);
          seqBuf.writeBigUInt64BE(keys.clientSeqNum);
          keys.clientSeqNum++;
          const macInput = Buffer.concat([
            seqBuf,
            Buffer.from([0x16, recordVersion[0], recordVersion[1]]),
            Buffer.from([(clientFinishedPlaintext.length >> 8) & 0xFF, clientFinishedPlaintext.length & 0xFF]),
            clientFinishedPlaintext,
          ]);
          const expectedMAC = crypto.createHmac('sha1', keys.clientWriteMAC).update(macInput).digest();
          console.log(`[SSL] Expected client MAC: ${expectedMAC.toString('hex')}`);
          console.log(`[SSL] Actual client MAC:   ${clientFinishedMAC.toString('hex')}`);
          
          if (clientFinishedMAC.equals(expectedMAC)) {
            console.log('[SSL] ✓ Client Finished MAC MATCHES!');
          } else {
            console.log('[SSL] ✗ Client Finished MAC MISMATCH (continuing anyway)');
          }
          
          // NOW add client's Finished to the handshake hash
          // This is the critical fix: server Finished hash must include client Finished
          socket._allHS.push(Buffer.from(clientFinishedPlaintext));
          
          // NOW compute and send server's ChangeCipherSpec + Finished
          // Send ChangeCipherSpec (not encrypted, not part of handshake hash)
          socket.write(wrapRecord(0x14, recordVersion, Buffer.from([0x01])));
          console.log('[SSL] Sent server ChangeCipherSpec');
          
          // Compute server Finished with ALL messages including client's Finished
          const allHSBuf = Buffer.concat(socket._allHS);
          console.log(`[SSL] Server Finished hash input: ${socket._allHS.length} messages, total ${allHSBuf.length} bytes`);
          for (let i = 0; i < socket._allHS.length; i++) {
            console.log(`[SSL]   msg[${i}]: ${socket._allHS[i].length} bytes, starts=0x${socket._allHS[i][0].toString(16)}`);
          }
          
          const verifyData = tls12PRF(keys.masterSecret, 'server finished',
            crypto.createHash('sha256').update(allHSBuf).digest(), 12);
          console.log(`[SSL] Server verify_data: ${verifyData.toString('hex')}`);
          
          const finishedMsg = wrapHandshake(0x14, verifyData);
          
          // Encrypt server Finished with RC4
          const encrypted = encryptRecord(0x16, recordVersion, finishedMsg,
            keys.serverWriteKey, keys.serverWriteMAC, keys, selectedCipher);
          socket.write(encrypted);
          console.log('[SSL] Sent encrypted server Finished');
          
          phase = 'established';
          
          // Handshake complete! Set up encrypted Blaze handler
          // Pass remaining pendingBuf in case app data arrived in same TCP segment
          const leftover = pendingBuf.subarray(offset + 5 + recLen);
          pendingBuf = Buffer.alloc(0); // clear it
          socket.removeAllListeners('data');
          setupEncryptedBlazeHandler(socket, keys, selectedCipher, leftover);
          console.log('[SSL] === HANDSHAKE COMPLETE === Waiting for Blaze data...');
          return; // exit the loop since we swapped handlers
        } else if (recType === 0x15) {
          // Alert
          console.log(`[SSL] Alert: level=${recBody[0]} desc=${recBody[1]}`);
        }

        offset += 5 + recLen;
      }
      pendingBuf = pendingBuf.subarray(offset);
    }
  });

  // NOW send the handshake messages (listener is already set up above)
  // Send handshake messages as separate TLS records
  const serverHelloRecord = wrapRecord(0x16, recordVersion, serverHelloMsg);
  const certRecord = wrapRecord(0x16, recordVersion, certMsg);
  const helloDoneRecord = wrapRecord(0x16, recordVersion, helloDoneMsg);
  
  console.log(`[SSL] Sending ServerHello (${serverHelloRecord.length}b) + Certificate (${certRecord.length}b) + ServerHelloDone (${helloDoneRecord.length}b)`);
  socket.write(Buffer.concat([serverHelloRecord, certRecord, helloDoneRecord]));
  console.log(`[SSL] Sent all handshake messages. Waiting for ClientKeyExchange...`);
}

// TLS 1.2 PRF (SHA-256 based, single hash)
function tls12PRF(secret, label, seed, length) {
  const labelBuf = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBuf, seed]);
  return pHash('sha256', secret, fullSeed, length);
}

// TLS PRF (used for key derivation and Finished in TLS 1.0+)
function tlsPRF(secret, label, seed, length) {
  const labelBuf = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBuf, seed]);
  const half = Math.ceil(secret.length / 2);
  const s1 = secret.subarray(0, half);
  const s2 = secret.subarray(secret.length - half);
  const md5Result = pHash('md5', s1, fullSeed, length);
  const sha1Result = pHash('sha1', s2, fullSeed, length);
  const result = Buffer.alloc(length);
  for (let i = 0; i < length; i++) result[i] = md5Result[i] ^ sha1Result[i];
  return result;
}

function pHash(algo, secret, seed, length) {
  const output = [];
  let a = seed;
  while (Buffer.concat(output).length < length) {
    a = crypto.createHmac(algo, secret).update(a).digest();
    output.push(crypto.createHmac(algo, secret).update(Buffer.concat([a, seed])).digest());
  }
  return Buffer.concat(output).subarray(0, length);
}

// SSLv3 PRF (used as fallback)
function ssl3PRF(secret, seed, length) {
  const output = [];
  let label = 0x41;
  while (Buffer.concat(output).length < length) {
    const labelStr = Buffer.alloc(label - 0x40, label);
    const sha1 = crypto.createHash('sha1').update(Buffer.concat([labelStr, secret, seed])).digest();
    const md5 = crypto.createHash('md5').update(Buffer.concat([secret, sha1])).digest();
    output.push(md5);
    label++;
  }
  return Buffer.concat(output).subarray(0, length);
}

function deriveKeys(preMasterSecret, clientRandom, serverRandom, cipher) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  // TLS 1.2 PRF uses SHA-256 only (not MD5+SHA1 split)
  const masterSecret = tls12PRF(preMasterSecret, 'master secret', seed, 48);
  
  const keySeed = Buffer.concat([serverRandom, clientRandom]);
  let macLen = 20, keyLen = 16, ivLen = 0;
  if (cipher === 0x002f) ivLen = 16;
  if (cipher === 0x0035) { keyLen = 32; ivLen = 16; }
  
  const totalNeeded = 2 * macLen + 2 * keyLen + 2 * ivLen;
  const keyBlock = tls12PRF(masterSecret, 'key expansion', keySeed, totalNeeded);
  
  let off = 0;
  const clientWriteMAC = keyBlock.subarray(off, off + macLen); off += macLen;
  const serverWriteMAC = keyBlock.subarray(off, off + macLen); off += macLen;
  const clientWriteKey = keyBlock.subarray(off, off + keyLen); off += keyLen;
  const serverWriteKey = keyBlock.subarray(off, off + keyLen); off += keyLen;
  const clientWriteIV = keyBlock.subarray(off, off + ivLen); off += ivLen;
  const serverWriteIV = keyBlock.subarray(off, off + ivLen); off += ivLen;

  return { masterSecret, clientWriteMAC, serverWriteMAC, clientWriteKey, serverWriteKey, clientWriteIV, serverWriteIV, cipher, serverSeqNum: BigInt(0), clientSeqNum: BigInt(0) };
}

function encryptRecord(type, version, plaintext, writeKey, writeMAC, keys, cipher) {
  // TLS 1.0 MAC: HMAC-SHA1(mac_key, seq_num + type + version + length + data)
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(keys.serverSeqNum);
  keys.serverSeqNum++;
  
  const macInput = Buffer.concat([
    seqBuf,
    Buffer.from([type, version[0], version[1]]),
    Buffer.from([(plaintext.length >> 8) & 0xFF, plaintext.length & 0xFF]),
    plaintext,
  ]);
  const mac = crypto.createHmac('sha1', writeMAC).update(macInput).digest();
  
  let encrypted;
  if (cipher === 0x0005 || cipher === 0x0004) {
    // RC4 stream cipher
    if (!keys._serverRC4) {
      keys._serverRC4 = crypto.createCipheriv('rc4', writeKey, Buffer.alloc(0));
    }
    encrypted = keys._serverRC4.update(Buffer.concat([plaintext, mac]));
  } else {
    // AES-CBC
    const iv = crypto.randomBytes(16);
    const padLen = 16 - ((plaintext.length + mac.length + 1) % 16);
    const padding = Buffer.alloc(padLen + 1, padLen);
    const aes = crypto.createCipheriv(cipher === 0x0035 ? 'aes-256-cbc' : 'aes-128-cbc', writeKey, iv);
    aes.setAutoPadding(false);
    encrypted = Buffer.concat([iv, aes.update(Buffer.concat([plaintext, mac, padding])), aes.final()]);
  }
  
  return wrapRecord(type, version, encrypted);
}

function decryptRecord(type, version, ciphertext, readKey, readMAC, keys, cipher) {
  let decrypted;
  if (cipher === 0x0005 || cipher === 0x0004) {
    if (!keys._clientRC4) {
      keys._clientRC4 = crypto.createDecipheriv('rc4', readKey, Buffer.alloc(0));
    }
    decrypted = keys._clientRC4.update(ciphertext);
  } else {
    const iv = ciphertext.subarray(0, 16);
    const aes = crypto.createDecipheriv(cipher === 0x0035 ? 'aes-256-cbc' : 'aes-128-cbc', readKey, iv);
    aes.setAutoPadding(false);
    decrypted = Buffer.concat([aes.update(ciphertext.subarray(16)), aes.final()]);
    // Remove padding
    const padLen = decrypted[decrypted.length - 1];
    decrypted = decrypted.subarray(0, decrypted.length - padLen - 1);
  }
  
  // Remove MAC (last 20 bytes)
  const plaintext = decrypted.subarray(0, decrypted.length - 20);
  keys.clientSeqNum++;
  return plaintext;
}

function setupEncryptedBlazeHandler(socket, keys, cipher, initialPendingBuf) {
  let pendingBuf = initialPendingBuf || Buffer.alloc(0);
  let blazeBuf = Buffer.alloc(0);

  function processPending() {
    // Parse TLS records
    while (pendingBuf.length >= 5) {
      const recType = pendingBuf[0];
      const recVer = (pendingBuf[1] << 8) | pendingBuf[2];
      const recLen = (pendingBuf[3] << 8) | pendingBuf[4];
      console.log(`[SSL] TLS record: type=0x${recType.toString(16)} ver=0x${recVer.toString(16)} len=${recLen} (pending: ${pendingBuf.length})`);
      if (pendingBuf.length < 5 + recLen) break;

      const recBody = pendingBuf.subarray(5, 5 + recLen);
      pendingBuf = pendingBuf.subarray(5 + recLen);

      if (recType === 0x17) {
        // Application data - decrypt it
        try {
          const plaintext = decryptRecord(0x17, [0x03, 0x03], recBody, keys.clientWriteKey, keys.clientWriteMAC, keys, cipher);
          console.log(`[SSL] Decrypted ${plaintext.length} bytes of application data`);
          
          // Feed into application buffer
          blazeBuf = Buffer.concat([blazeBuf, plaintext]);
          
          // Log raw decrypted application data hex (first 32 bytes)
          const hexDump = Array.from(plaintext.subarray(0, Math.min(plaintext.length, 32))).map(b => b.toString(16).padStart(2, '0')).join(' ');
          console.log(`[SSL] Raw app data (${plaintext.length}b): ${hexDump}`);
          
          // Check if this is HTTP or raw Blaze
          const firstLine = blazeBuf.toString('ascii', 0, Math.min(blazeBuf.length, 20));
          
          if (firstLine.startsWith('POST ') || firstLine.startsWith('GET ') || firstLine.startsWith('HTTP')) {
            // HTTP-wrapped Blaze request
            handleHttpBlazeRequest(blazeBuf, socket, keys, cipher);
            blazeBuf = Buffer.alloc(0); // consumed
          } else {
            // Raw Blaze binary
            let result = readPacket(blazeBuf);
            while (result) {
              blazeBuf = result.remaining;
              const pkt = result.packet;
              console.log(`[Blaze-Enc] comp=0x${pkt.header.component.toString(16).padStart(4,'0')} cmd=0x${pkt.header.command.toString(16).padStart(4,'0')} len=${pkt.header.length} msgType=0x${pkt.header.msgType.toString(16)} msgId=${pkt.header.msgId} err=${pkt.header.error}`);
              const resp = handleBlazePacket(pkt);
              if (resp) {
                // Log response header bytes and sweep info
                const sv = SWEEP_VALUES[sweepIndex % SWEEP_VALUES.length];
                console.log(`[SWEEP#${sweepIndex}] ${sv[2]} | resp: ${Array.from(resp.subarray(0, Math.min(resp.length, 16))).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
                const encReply = encryptRecord(0x17, [0x03, 0x03], resp, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
                socket.write(encReply);
                console.log(`[Blaze-Enc] Sent encrypted reply (${resp.length} bytes)`);
                
                // DISABLED: Proactive notifications were confusing the game
                // The DLL v97 patch now handles post-PreAuth flow directly
                if (false && pkt.header.component === 0x0009 && pkt.header.command === 0x0007) {
                  console.log('[Blaze-Enc] Sending proactive login sequence after PreAuth...');
                  
                  // 1. SilentLogin response (comp=0x0001, cmd=0x0032)
                  const loginEnc = new TdfEncoder();
                  loginEnc.writeInteger('AGUP', 0);
                  loginEnc.writeString('LDHT', '');
                  loginEnc.writeInteger('NTOS', 0);
                  loginEnc.writeString('PCTK', 'FakeAuthToken_FIFA17');
                  loginEnc.writeString('PRIV', '');
                  loginEnc.writeStructStart('SESS');
                  loginEnc.writeInteger('BUID', 1000000001);
                  loginEnc.writeInteger('FRST', 0);
                  loginEnc.writeString('KEY ', 'SessionKey_12345');
                  loginEnc.writeInteger('LLOG', 0);
                  loginEnc.writeString('MAIL', 'player@fut.local');
                  loginEnc.writeStructStart('PDTL');
                  loginEnc.writeString('DSNM', 'Player');
                  loginEnc.writeInteger('LAST', 0);
                  loginEnc.writeInteger('PID ', 1000000001);
                  loginEnc.writeInteger('STAS', 0);
                  loginEnc.writeInteger('XREF', 0);
                  loginEnc.writeInteger('XTYP', 0);
                  loginEnc.writeStructEnd(); // PDTL
                  loginEnc.writeInteger('UID ', 2000000001);
                  loginEnc.writeStructEnd(); // SESS
                  loginEnc.writeInteger('SPAM', 0);
                  loginEnc.writeString('THST', '');
                  loginEnc.writeString('TSUI', '');
                  loginEnc.writeString('TURI', '');
                  const loginBody = loginEnc.build();
                  // Send as SilentLogin NOTIFICATION (msgType=0x2000, not response)
                  const loginHdr = encodeHeader({ length: loginBody.length, component: 0x0001, command: 0x0032, error: 0, notify: true });
                  const loginPkt = Buffer.concat([loginHdr, loginBody]);
                  const encLogin = encryptRecord(0x17, [0x03, 0x03], loginPkt, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
                  socket.write(encLogin);
                  console.log(`[Blaze-Enc] Sent proactive SilentLogin (${loginPkt.length} bytes)`);
                  
                  // 2. PostAuth response (comp=0x0009, cmd=0x0008)
                  const postEnc = new TdfEncoder();
                  // Telemetry config
                  postEnc.writeStructStart('TELE');
                  postEnc.writeString('ADRS', '127.0.0.1');
                  postEnc.writeInteger('ANON', 0);
                  postEnc.writeString('DPTS', 'ut/bf/fifa17');
                  postEnc.writeInteger('LOC ', 1701729619);
                  postEnc.writeString('NOOK', '');
                  postEnc.writeInteger('PORT', 9988);
                  postEnc.writeInteger('SDLY', 15000);
                  postEnc.writeString('SESS', 'telemetry_session');
                  postEnc.writeString('SKEY', 'telemetry_key');
                  postEnc.writeInteger('SPCT', 75);
                  postEnc.writeString('STIM', '');
                  postEnc.writeStructEnd();
                  const postBody = postEnc.build();
                  const postHdr = encodeHeader({ length: postBody.length, component: 0x0009, command: 0x0008, error: 0, notify: true });
                  const postPkt = Buffer.concat([postHdr, postBody]);
                  const encPost = encryptRecord(0x17, [0x03, 0x03], postPkt, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
                  socket.write(encPost);
                  console.log(`[Blaze-Enc] Sent proactive PostAuth (${postPkt.length} bytes)`);
                  
                  // 3. UserSession notification (comp=0x7802, cmd=0x0002) - async
                  const userEnc = new TdfEncoder();
                  userEnc.writeStructStart('USER');
                  userEnc.writeInteger('AID ', 2000000001);
                  userEnc.writeInteger('ALOC', 1701729619);
                  userEnc.writeInteger('ID  ', 1000000001);
                  userEnc.writeString('NAME', 'Player');
                  userEnc.writeStructEnd();
                  const userBody = userEnc.build();
                  const userHdr = encodeHeader({ length: userBody.length, component: 0x7802, command: 0x0002, error: 0, notify: true });
                  const userPkt = Buffer.concat([userHdr, userBody]);
                  const encUser = encryptRecord(0x17, [0x03, 0x03], userPkt, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
                  socket.write(encUser);
                  console.log(`[Blaze-Enc] Sent proactive UserSession (${userPkt.length} bytes)`);
                }
              }
              result = readPacket(blazeBuf);
            }
          }
        } catch (e) {
          console.log(`[SSL] Decryption error: ${e.message}`);
          console.log(`[SSL] Stack: ${e.stack}`);
        }
      } else if (recType === 0x15) {
        // Log raw record bytes BEFORE trying to decrypt
        console.log(`[SSL] Record type 0x15 (alert?), raw body (${recBody.length} bytes): ${Array.from(recBody).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        try {
          // Decrypt but also verify MAC
          let decrypted;
          if (cipher === 0x0005 || cipher === 0x0004) {
            if (!keys._clientRC4) {
              keys._clientRC4 = crypto.createDecipheriv('rc4', keys.clientWriteKey, Buffer.alloc(0));
            }
            decrypted = keys._clientRC4.update(recBody);
          }
          const plaintext = decrypted.subarray(0, decrypted.length - 20);
          const mac = decrypted.subarray(decrypted.length - 20);
          
          // Verify MAC
          const seqBuf = Buffer.alloc(8);
          seqBuf.writeBigUInt64BE(keys.clientSeqNum);
          keys.clientSeqNum++;
          const macInput = Buffer.concat([
            seqBuf,
            Buffer.from([0x15, 0x03, 0x03]),
            Buffer.from([(plaintext.length >> 8) & 0xFF, plaintext.length & 0xFF]),
            plaintext,
          ]);
          const expectedMAC = crypto.createHmac('sha1', keys.clientWriteMAC).update(macInput).digest();
          
          console.log(`[SSL] Alert decrypted: ${Array.from(plaintext).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
          console.log(`[SSL] Alert MAC match: ${mac.equals(expectedMAC)}`);
          console.log(`[SSL] Alert: level=${plaintext[0]} desc=${plaintext[1]}`);
          
          if (!mac.equals(expectedMAC)) {
            console.log(`[SSL] MAC MISMATCH - this might not be a real alert!`);
            console.log(`[SSL] Expected MAC: ${expectedMAC.toString('hex')}`);
            console.log(`[SSL] Actual MAC:   ${mac.toString('hex')}`);
          }
        } catch (e) {
          console.log(`[SSL] Alert processing error: ${e.message}`);
        }
      } else {
        console.log(`[SSL] Unknown record type 0x${recType.toString(16)} len=${recLen}`);
      }
    }
  }

  socket.on('data', (data) => {
    console.log(`[SSL-DATA] Received ${data.length} bytes on socket (total pending: ${pendingBuf.length + data.length})`);
    pendingBuf = Buffer.concat([pendingBuf, data]);
    processPending();
  });

  socket.on('close', () => console.log('[SSL-CONN] Socket closed'));
  socket.on('error', (e) => console.log(`[SSL-CONN] Socket error: ${e.message}`));

  if (pendingBuf.length > 0) {
    console.log(`[SSL] Processing ${pendingBuf.length} bytes of leftover data from handshake`);
    processPending();
  }
}

// Handle HTTP-wrapped Blaze requests (game sends POST /redirector/getServerInstance HTTP/1.1)
function handleHttpBlazeRequest(data, socket, keys, cipher) {
  const text = data.toString('ascii');
  console.log(`[HTTP-Blaze] Request:\n${text.substring(0, 500)}`);
  
  // Parse the HTTP request
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    console.log('[HTTP-Blaze] Incomplete HTTP request (no header end)');
    return;
  }
  
  const headerText = text.substring(0, headerEnd);
  const body = data.subarray(headerEnd + 4);
  const firstLine = headerText.split('\r\n')[0];
  const [method, path] = firstLine.split(' ');
  
  console.log(`[HTTP-Blaze] ${method} ${path} (body: ${body.length} bytes)`);
  
  let responseBody;
  let contentType = 'application/xml';
  
  if (path === '/redirector/getServerInstance') {
    console.log(`[HTTP-Blaze] GetServerInstance -> ${TARGET_HOST}:${MAIN_BLAZE_PORT}`);
    const secure = process.env.REDIRECT_SECURE || '0';
    console.log(`[HTTP-Blaze] secure=${secure}`);
    responseBody = Buffer.from(
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<serverinstanceinfo>\n' +
      `  <address member="0">\n` +
      `    <valu>\n` +
      `      <hostname>${TARGET_HOST}</hostname>\n` +
      `      <ip>${ipToInt(TARGET_HOST)}</ip>\n` +
      `      <port>${MAIN_BLAZE_PORT}</port>\n` +
      `    </valu>\n` +
      `  </address>\n` +
      `  <secure>${secure}</secure>\n` +
      `  <triallogin>0</triallogin>\n` +
      `  <defaultdnsaddress>0</defaultdnsaddress>\n` +
      '</serverinstanceinfo>\n'
    );
  } else {
    console.log(`[HTTP-Blaze] Unknown path: ${path}`);
    responseBody = Buffer.from('<?xml version="1.0" encoding="UTF-8"?>\n<response></response>\n');
  }
  
  const httpResponse = Buffer.from(
    `HTTP/1.1 200 OK\r\n` +
    `Content-Type: ${contentType}\r\n` +
    `Content-Length: ${responseBody.length}\r\n` +
    `Connection: keep-alive\r\n` +
    `\r\n`
  );
  
  const fullResponse = Buffer.concat([httpResponse, responseBody]);
  console.log(`[HTTP-Blaze] Response (${fullResponse.length} bytes):\n${fullResponse.toString('ascii').substring(0, 300)}`);
  
  // Encrypt and send
  const encrypted = encryptRecord(0x17, [0x03, 0x03], fullResponse, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
  socket.write(encrypted);
  console.log(`[HTTP-Blaze] Sent encrypted HTTP response`);
}

// Generic Blaze packet handler for both redirector and main server
function handleBlazePacket(pkt) {
  const { component: comp, command: cmd } = pkt.header;
  const session = { id: 1, personaId: 1000000001, nucleusId: 2000000001, displayName: 'Player1', auth: true };
  
  // Handle Ping packets (type=4) — echo back
  if (comp === 0x0000 && cmd === 0x0000 && pkt.header.msgType === 4) {
    console.log(`[Blaze] Ping (msgId=${pkt.header.msgId}), sending pong`);
    const pong = Buffer.alloc(HEADER_SIZE);
    const mid = pkt.header.msgId;
    pong[10] = (mid >> 16) & 0xFF;
    pong[11] = (mid >> 8) & 0xFF;
    pong[12] = mid & 0xFF;
    pong[13] = 0x80;
    return pong;
  }
  // Skip other null packets
  if (comp === 0x0000 && cmd === 0x0000) {
    console.log(`[Blaze] Ignoring null packet (msgId=${pkt.header.msgId} type=${pkt.header.msgType})`);
    return null;
  }
  
  if (comp === 0x0005 && cmd === 0x0001) {
    console.log(`[Blaze] GetServerInstance -> ${TARGET_HOST}:${MAIN_BLAZE_PORT}`);
    const enc = new TdfEncoder();
    enc.writeUnion('ADDR', 0x00, (e) => {
      e.writeStructStart('VALU');
      e.writeString('HOST', TARGET_HOST);
      e.writeInteger('IP  ', ipToInt(TARGET_HOST));
      e.writeInteger('PORT', MAIN_BLAZE_PORT);
      e.writeStructEnd();
    });
    enc.writeInteger('SECU', 0);
    enc.writeInteger('XDNS', 0);
    return buildReply(pkt, enc.build());
  } else if (comp === 0x0009) {
    if (cmd === 0x0007) return handlePreAuth(pkt);
    if (cmd === 0x0008) return handlePostAuth(session, pkt);
    if (cmd === 0x0002) return handlePing(pkt);
    if (cmd === 0x0003) return handleGetTelemetry(pkt);
    if (cmd === 0x0001) return buildReply(pkt, new TdfEncoder().build());
    if (cmd === 0x000B) return buildReply(pkt, new TdfEncoder().writeString('SVAL', '').build());
    return buildReply(pkt, Buffer.alloc(0));
  } else if (comp === 0x0001) {
    if ([0x0028, 0x00C8, 0x0032, 0x003C].includes(cmd)) return handleLogin(session, pkt);
    if (cmd === 0x001D) return buildReply(pkt, new TdfEncoder().build());
    if (cmd === 0x0024) return buildReply(pkt, new TdfEncoder().writeString('AUTH', 'tok_1').build());
    if (cmd === 0x0030) return handleListPersona(session, pkt);
    if (cmd === 0x002A) return buildReply(pkt, new TdfEncoder().writeInteger('TOSI', 0).build());
    return buildReply(pkt, Buffer.alloc(0));
  } else if (comp === 0x7802) {
    return buildReply(pkt, Buffer.alloc(0));
  }
  console.log(`[Blaze] Unhandled comp=0x${comp.toString(16)} cmd=0x${cmd.toString(16)}`);
  return buildReply(pkt, Buffer.alloc(0));
}

function setupRedirectorHandler(socket) {
  handleBlazeStream(socket, 'Redirector', (pkt) => {
    console.log(`[Redirector] comp=0x${pkt.header.component.toString(16)} cmd=0x${pkt.header.command.toString(16)}`);
    if (pkt.header.component === 0x0005 && pkt.header.command === 0x0001) {
      console.log(`[Redirector] GetServerInstance -> ${TARGET_HOST}:${MAIN_BLAZE_PORT}`);
      const enc = new TdfEncoder();
      enc.writeUnion('ADDR', 0x00, (e) => {
        e.writeStructStart('VALU');
        e.writeString('HOST', TARGET_HOST);
        e.writeInteger('IP  ', ipToInt(TARGET_HOST));
        e.writeInteger('PORT', MAIN_BLAZE_PORT);
        e.writeStructEnd();
      });
      enc.writeInteger('SECU', 0);
      enc.writeInteger('XDNS', 0);
      socket.write(buildReply(pkt, enc.build()));
      setTimeout(() => socket.end(), 100);
    }
  });
  socket.on('close', () => console.log('[Redirector] Disconnected'));
  socket.on('error', (e) => console.log(`[Redirector] Error: ${e.message}`));
}

// ============================================================
// Main Blaze Server (port 10041)
// ============================================================

let nextSessionId = 1;
function startMainServer() {
  const server = net.createServer((socket) => {
    const sid = nextSessionId++;
    const session = { id: sid, socket, personaId: 1000000000 + sid, nucleusId: 2000000000 + sid, displayName: `Player${sid}`, auth: false };
    console.log(`[Main] Session ${sid} connected: ${socket.remoteAddress}:${socket.remotePort}`);

    // Auto-detect protocol: accumulate data, log raw bytes, then decide
    let dataBuf = Buffer.alloc(0);
    let detected = false;
    const initialHandler = (data) => {
      if (detected) return;
      dataBuf = Buffer.concat([dataBuf, data]);
      
      // Log raw bytes for debugging
      console.log(`[Main] S${sid}: received ${data.length} bytes (total: ${dataBuf.length})`);
      for (let i = 0; i < Math.min(dataBuf.length, 64); i += 16) {
        const slice = dataBuf.subarray(i, Math.min(i + 16, dataBuf.length));
        const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(slice).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
        console.log(`[Main]   ${i.toString(16).padStart(4, '0')}: ${hex.padEnd(48)} ${ascii}`);
      }
      
      if (dataBuf.length < 5) return; // wait for more data
      detected = true;
      socket.removeListener('data', initialHandler);

      if (dataBuf[0] === 0x16 && dataBuf[1] === 0x03) {
        console.log(`[Main] S${sid}: TLS detected, starting handshake`);
        handleSSLv3Handshake(socket, dataBuf);
      } else {
        const peek = dataBuf.toString('ascii', 0, Math.min(dataBuf.length, 10));
        if (peek.startsWith('POST ') || peek.startsWith('GET ')) {
          console.log(`[Main] S${sid}: HTTP Blaze detected`);
          setupHttpBlazeMainHandler(socket, session);
          socket.emit('data', dataBuf);
        } else {
          // Raw Blaze binary (16-byte header, first 4 bytes = length)
          console.log(`[Main] S${sid}: Raw Blaze binary detected`);
          setupMainBlazeHandler(socket, session);
          socket.emit('data', dataBuf);
        }
      }
    };
    socket.on('data', initialHandler);
    socket.on('close', () => {
      console.log(`[Main] S${sid} disconnected`);
      flushAndPush(`S${sid} disconnect`);
    });
    socket.on('error', (e) => console.log(`[Main] S${sid} error: ${e.message}`));
  });
  server.listen(MAIN_BLAZE_PORT, '0.0.0.0', () => console.log(`[Main] Blaze server on port ${MAIN_BLAZE_PORT}`));
}

function setupMainBlazeHandler(socket, session) {
  const sid = session.id;
  handleBlazeStream(socket, `Main:${sid}`, (pkt) => {
    const { component: comp, command: cmd } = pkt.header;
    console.log(`[Main] S${sid}: comp=0x${comp.toString(16).padStart(4,'0')} cmd=0x${cmd.toString(16).padStart(4,'0')} len=${pkt.header.length} msgId=${pkt.header.msgId}`);
    let resp = null;
    try {
      // Handle Ping packets (type=4) — respond with PING_REPLY (type=5)
      if (comp === 0x0000 && cmd === 0x0000 && pkt.header.msgType === 4) {
        console.log(`[Main] S${sid}: -> Ping (msgId=${pkt.header.msgId}), sending pong`);
        // Echo the msgId but set type to 5 (PING_REPLY)
        const pong = Buffer.alloc(HEADER_SIZE);
        pong.writeUInt32BE(0, 0);           // length=0
        pong.writeUInt16BE(0, 4);           // ext=0
        pong.writeUInt16BE(0, 6);           // comp=0
        pong.writeUInt16BE(0, 8);           // cmd=0
        const mid = pkt.header.msgId;
        pong[10] = (mid >> 16) & 0xFF;
        pong[11] = (mid >> 8) & 0xFF;
        pong[12] = mid & 0xFF;
        pong[13] = 0xA0;                    // type=5 (PING_REPLY), flags=0
        pong.writeUInt16BE(0, 14);          // error=0
        socket.write(pong);
        return;
      }
      // Skip other null packets
      if (comp === 0x0000 && cmd === 0x0000) {
        console.log(`[Main] S${sid}: -> Ignoring null/error packet (msgId=${pkt.header.msgId} type=${pkt.header.msgType})`);
        return;
      }
      if (comp === 0x0009) {
        if (cmd === 0x0007) { console.log(`[Main] S${sid}: -> PreAuth`); resp = handlePreAuth(pkt); }
        else if (cmd === 0x0008) { console.log(`[Main] S${sid}: -> PostAuth`); resp = handlePostAuth(session, pkt); }
        else if (cmd === 0x0002) resp = handlePing(pkt);
        else if (cmd === 0x0003) resp = handleGetTelemetry(pkt);
        else if (cmd === 0x0001) {
          // FetchClientConfig — decode the CFID to see what config is requested
          try {
            const decoded = decodeTdf(pkt.body);
            const cfidLine = decoded.lines.find(l => l.includes('CFID'));
            console.log(`[Main] S${sid}: -> FetchClientConfig: ${cfidLine || 'unknown'}`);
          } catch(e) { console.log(`[Main] S${sid}: -> FetchClientConfig (decode err)`); }
          resp = handleFetchClientConfig(pkt);
        }
        else if (cmd === 0x000B) resp = buildReply(pkt, new TdfEncoder().writeString('SVAL', '').build());
        else { console.log(`[Main] S${sid}: -> Util unknown cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      } else if (comp === 0x0001) {
        // Authentication component — log ALL requests with TDF body
        console.log(`[Main] S${sid}: -> Auth cmd=0x${cmd.toString(16)} (${cmd === 0x0A ? 'CreateAccount' : cmd === 0x28 ? 'Login' : cmd === 0x32 ? 'SilentLogin' : cmd === 0x3C ? 'ExpressLogin' : cmd === 0x46 ? 'Logout' : cmd === 0x98 ? 'OriginLogin' : cmd === 0x1D ? 'ListEntitlements2' : cmd === 0x64 ? 'ListPersonas' : 'unknown'})`);
        try {
          const decoded = decodeTdf(pkt.body);
          for (const line of decoded.lines) console.log(`[Main] S${sid}:   ${line}`);
        } catch(e) { if (pkt.body.length > 0) console.log(`[Main] S${sid}:   (${pkt.body.length} bytes, decode err)`); }
        
        if (cmd === 0x000A) { 
          resp = handleCreateAccount(session, pkt);
        }
        else if (cmd === 0x0046) {
          // Logout — ack with EMPTY TDF (do NOT send login payload; that confuses the game)
          console.log(`[Main] S${sid}: -> Logout (ack with empty response)`);
          resp = buildReply(pkt, Buffer.alloc(0));
        }
        else if ([0x0028, 0x00C8, 0x0032, 0x003C, 0x0098].includes(cmd)) {
          resp = handleLogin(session, pkt);
          
          // Schedule post-login notifications after the response is sent
          // These tell the game "you are authenticated" via notification handlers
          // that don't need msgId matching
          const notifSocket = socket;
          const notifSession = session;
          setTimeout(() => {
            try {
              // NotifyUserAdded (comp=0x7802, cmd=0x0002, type=notification)
              const ua = new TdfEncoder();
              ua.writeStructStart('USER');
              ua.writeInteger('AID ', notifSession.nucleusId);
              ua.writeInteger('ALOC', 1701729619);
              ua.writeInteger('ID  ', notifSession.personaId);
              ua.writeString('NAME', notifSession.displayName);
              ua.writeStructEnd();
              const uaBody = ua.build();
              const uaHdr = encodeHeader({ length: uaBody.length, component: 0x7802, command: 0x0002, error: 0, notify: true });
              notifSocket.write(Buffer.concat([uaHdr, uaBody]));
              console.log(`[Main] S${sid}: >> NotifyUserAdded sent (${uaBody.length} bytes)`);
            } catch(e) { console.log(`[Main] S${sid}: NotifyUserAdded error: ${e.message}`); }
          }, 300);
          
          setTimeout(() => {
            try {
              // UserSessionExtendedDataUpdate (comp=0x7802, cmd=0x0001, type=notification)
              const ue = new TdfEncoder();
              ue.writeStructStart('DATA');
              ue.writeInteger('ADDR', 0);  // network address union (simplified)
              ue.writeStructEnd();
              ue.writeInteger('USID', notifSession.personaId);
              const ueBody = ue.build();
              const ueHdr = encodeHeader({ length: ueBody.length, component: 0x7802, command: 0x0001, error: 0, notify: true });
              notifSocket.write(Buffer.concat([ueHdr, ueBody]));
              console.log(`[Main] S${sid}: >> UserSessionExtendedDataUpdate sent (${ueBody.length} bytes)`);
            } catch(e) { console.log(`[Main] S${sid}: ExtendedDataUpdate error: ${e.message}`); }
          }, 500);
          
          setTimeout(() => {
            try {
              // UserUpdated / NotifyUserUpdated (comp=0x7802, cmd=0x0005, type=notification)
              const uu = new TdfEncoder();
              uu.writeInteger('FLGS', 3);
              uu.writeInteger('ID  ', notifSession.personaId);
              const uuBody = uu.build();
              const uuHdr = encodeHeader({ length: uuBody.length, component: 0x7802, command: 0x0005, error: 0, notify: true });
              notifSocket.write(Buffer.concat([uuHdr, uuBody]));
              console.log(`[Main] S${sid}: >> UserUpdated sent (${uuBody.length} bytes)`);
            } catch(e) { console.log(`[Main] S${sid}: UserUpdated error: ${e.message}`); }
          }, 700);
        }
        else if (cmd === 0x001D) resp = buildReply(pkt, new TdfEncoder().build());
        else if (cmd === 0x0024) resp = buildReply(pkt, new TdfEncoder().writeString('AUTH', `tok_${sid}`).build());
        else if (cmd === 0x0030) { console.log(`[Main] S${sid}: -> ListPersonas`); resp = handleListPersona(session, pkt); }
        else if (cmd === 0x002A) resp = buildReply(pkt, new TdfEncoder().writeInteger('TOSI', 0).build());
        else if (cmd === 0x00F2) {
          // GetLegalDocsInfo — return legal doc info
          // PocketRelay format: EAMC(int), LHST(str), PMC(int), PPUI(str), TSUI(str)
          console.log(`[Main] S${sid}: -> GetLegalDocsInfo`);
          const enc = new TdfEncoder();
          enc.writeInteger('EAMC', 0);
          enc.writeString('LHST', '');
          enc.writeInteger('PMC ', 0);
          enc.writeString('PPUI', '');
          enc.writeString('TSUI', '');
          resp = buildReply(pkt, enc.build());
        }
        else if (cmd === 0x00F6) {
          // GetTermsOfServiceContent — return TOS content
          // PocketRelay format: LDVC(str path), TCOL(u16), TCOT(str content)
          console.log(`[Main] S${sid}: -> GetTermsOfServiceContent`);
          const enc = new TdfEncoder();
          enc.writeString('LDVC', 'webterms/au/en/pc/default/09082020/02042022');
          enc.writeInteger('TCOL', 0);
          enc.writeString('TCOT', 'Terms of Service: You agree to play FIFA 17 on this private server.');
          resp = buildReply(pkt, enc.build());
        }
        else if (cmd === 0x002F) {
          // GetPrivacyPolicyContent — return privacy policy
          // PocketRelay format: LDVC(str path), TCOL(u16), TCOT(str content)
          console.log(`[Main] S${sid}: -> GetPrivacyPolicyContent`);
          const enc = new TdfEncoder();
          enc.writeString('LDVC', 'webprivacy/au/en/pc/default/08202020/02042022');
          enc.writeInteger('TCOL', 0);
          enc.writeString('TCOT', 'Privacy Policy: No personal data is collected or shared.');
          resp = buildReply(pkt, enc.build());
        }
        else { console.log(`[Main] S${sid}: -> Auth unknown cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      } else if (comp === 0x7802) { resp = buildReply(pkt, Buffer.alloc(0)); }
      else { console.log(`[Main] S${sid}: -> Unhandled comp=0x${comp.toString(16)} cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      if (resp) {
        console.log(`[Main] S${sid}: Sending response (${resp.length} bytes)`);
        const hdrHex = Array.from(resp.subarray(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`[Main] S${sid}: header: ${hdrHex}`);
        socket.write(resp);
        
        // Proactive notifications after PreAuth:
        // The game's FIFA online layer is waiting for a server-initiated SilentLogin
        // notification to transition from "fetching auth" state to "authenticated".
        // Without this, the game gives up after FetchClientConfig and sends Logout.
        if (comp === 0x0009 && cmd === 0x0007 && !session.loginSent) {
          session.loginSent = true;
          console.log(`[Main] S${sid}: Sending proactive SilentLogin notification after PreAuth`);
          
          // Build a SilentLogin notification (comp=0x0001, cmd=0x0032, notify=true)
          const le = new TdfEncoder();
          le.writeInteger('AGUP', 0);
          le.writeString('LDHT', '');
          le.writeInteger('NTOS', 0);
          le.writeString('PCTK', `tok_${sid}`);
          le.writeString('PRIV', '');
          le.writeStructStart('SESS');
            le.writeInteger('BUID', session.nucleusId);
            le.writeInteger('FRST', 0);
            le.writeString('KEY ', `sk_${sid}`);
            le.writeInteger('LLOG', 0);
            le.writeString('MAIL', `p${sid}@fut.local`);
            le.writeStructStart('PDTL');
              le.writeString('DSNM', session.displayName);
              le.writeInteger('LAST', 0);
              le.writeInteger('PID ', session.personaId);
              le.writeInteger('STAS', 0);
              le.writeInteger('XREF', 0);
              le.writeInteger('XTYP', 0);
            le.writeStructEnd();
            le.writeInteger('UID ', session.nucleusId);
          le.writeStructEnd();
          le.writeInteger('SPAM', 0);
          le.writeString('THST', '');
          le.writeString('TSUI', '');
          le.writeString('TURI', '');
          const lb = le.build();
          const lh = encodeHeader({ length: lb.length, component: 0x0001, command: 0x0032, error: 0, notify: true });
          socket.write(Buffer.concat([lh, lb]));
          console.log(`[Main] S${sid}: SilentLogin notification sent (${lb.length} bytes)`);
        }
      }
    } catch (e) {
      console.log(`[Main] S${sid}: ERROR handling packet: ${e.message}`);
      console.log(`[Main] S${sid}: Stack: ${e.stack}`);
    }
  });
}

// HTTP-wrapped Blaze handler for the main server
function setupHttpBlazeMainHandler(socket, session) {
  const sid = session.id;
  let httpBuf = Buffer.alloc(0);
  
  socket.on('data', (data) => {
    httpBuf = Buffer.concat([httpBuf, data]);
    
    // Try to parse complete HTTP requests
    while (httpBuf.length > 0) {
      const text = httpBuf.toString('ascii');
      const headerEnd = text.indexOf('\r\n\r\n');
      if (headerEnd === -1) break; // incomplete headers
      
      const headerText = text.substring(0, headerEnd);
      const headers = {};
      const lines = headerText.split('\r\n');
      const firstLine = lines[0];
      for (let i = 1; i < lines.length; i++) {
        const colon = lines[i].indexOf(':');
        if (colon > 0) headers[lines[i].substring(0, colon).trim().toLowerCase()] = lines[i].substring(colon + 1).trim();
      }
      
      const contentLength = parseInt(headers['content-length'] || '0');
      const totalLen = headerEnd + 4 + contentLength;
      if (httpBuf.length < totalLen) break; // incomplete body
      
      const body = httpBuf.subarray(headerEnd + 4, totalLen);
      httpBuf = httpBuf.subarray(totalLen);
      
      const [method, path] = firstLine.split(' ');
      const bodyText = body.toString('utf-8');
      console.log(`[Main-HTTP] S${sid}: ${method} ${path} (${contentLength} bytes)`);
      console.log(`[Main-HTTP] Body: ${bodyText.substring(0, 500)}`);
      
      // Route based on path
      const responseXml = handleMainHttpRoute(path, bodyText, session);
      
      const responseBody = Buffer.from(responseXml, 'utf-8');
      const httpResponse = Buffer.from(
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: application/xml\r\n` +
        `Content-Length: ${responseBody.length}\r\n` +
        `Connection: keep-alive\r\n` +
        `\r\n`
      );
      
      socket.write(Buffer.concat([httpResponse, responseBody]));
      console.log(`[Main-HTTP] S${sid}: Sent response for ${path} (${responseBody.length} bytes)`);
    }
  });
}

function handleMainHttpRoute(path, bodyXml, session) {
  console.log(`[Main-HTTP] Routing: ${path}`);
  
  // Extract component/command from path: /util/preAuth, /authentication/login, etc.
  const parts = path.split('/').filter(p => p);
  const component = parts[0] || '';
  const command = parts[1] || '';
  
  if (component === 'util') {
    if (command === 'preAuth' || command === 'pre-auth') {
      console.log('[Main-HTTP] PreAuth');
      return `<?xml version="1.0" encoding="UTF-8"?>
<preauth>
  <componentids>
    <id>1</id><id>4</id><id>5</id><id>7</id><id>9</id><id>15</id><id>25</id><id>28</id><id>30722</id>
  </componentids>
  <serverconfig>
    <config>{}</config>
  </serverconfig>
  <serverinstance>fifa17-fut-server</serverinstance>
  <namespace>cem_ea_id</namespace>
  <personaid></personaid>
  <platform>pc</platform>
  <qosconfig>
    <bandwidthpingsite>
      <address>127.0.0.1</address>
      <port>17502</port>
      <sitename>prod-sjc</sitename>
    </bandwidthpingsite>
    <latenecyping>10</latenecyping>
    <serverid>1162281989</serverid>
  </qosconfig>
  <resource>fifa17-2016</resource>
  <serverversion>Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)</serverversion>
</preauth>`;
    }
    if (command === 'postAuth' || command === 'post-auth') {
      console.log('[Main-HTTP] PostAuth');
      return `<?xml version="1.0" encoding="UTF-8"?>
<postauth>
  <telemetry>
    <address>127.0.0.1</address>
    <anonymous>0</anonymous>
    <datapointtags>ut/bf/fifa17</datapointtags>
    <locale>1701729619</locale>
    <nook></nook>
    <port>9988</port>
    <senddelay>15000</senddelay>
    <session>JMhnT9dXSED</session>
    <sessionkey>key</sessionkey>
    <sendpercentage>75</sendpercentage>
    <sendtime></sendtime>
  </telemetry>
  <userroleoverride>
    <temporaryoverride>1</temporaryoverride>
    <userid>${session.nucleusId}</userid>
  </userroleoverride>
</postauth>`;
    }
    if (command === 'ping') {
      return `<?xml version="1.0" encoding="UTF-8"?>\n<ping><servertime>${Date.now()}</servertime></ping>`;
    }
    if (command === 'getTelemetryServer' || command === 'get-telemetry-server') {
      return `<?xml version="1.0" encoding="UTF-8"?>
<telemetryserver>
  <address>127.0.0.1</address>
  <anonymous>0</anonymous>
  <datapointtags>ut/bf/fifa17</datapointtags>
  <locale>1701729619</locale>
  <nook></nook>
  <port>9988</port>
  <senddelay>15000</senddelay>
  <session></session>
  <sessionkey></sessionkey>
  <sendpercentage>75</sendpercentage>
  <sendtime></sendtime>
</telemetryserver>`;
    }
    if (command === 'getUserOptions' || command === 'get-user-options') {
      return `<?xml version="1.0" encoding="UTF-8"?>\n<useroptions><telemetryoptout>0</telemetryoptout></useroptions>`;
    }
  }
  
  if (component === 'authentication') {
    if (command === 'login') {
      console.log('[Main-HTTP] Login');
      return `<?xml version="1.0" encoding="UTF-8"?>
<login>
  <agentid>0</agentid>
  <sessionkey>sk_${session.id}</sessionkey>
  <email>p${session.id}@fut.local</email>
  <personadetails>
    <displayname>${session.displayName}</displayname>
    <lastlogin>0</lastlogin>
    <personaid>${session.personaId}</personaid>
    <status>0</status>
    <externalreference>0</externalreference>
    <externaltype>0</externaltype>
  </personadetails>
  <userid>${session.nucleusId}</userid>
</login>`;
    }
    if (command === 'silentLogin' || command === 'silent-login') {
      return `<?xml version="1.0" encoding="UTF-8"?>
<login>
  <agentid>0</agentid>
  <sessionkey>sk_${session.id}</sessionkey>
  <email>p${session.id}@fut.local</email>
  <personadetails>
    <displayname>${session.displayName}</displayname>
    <lastlogin>0</lastlogin>
    <personaid>${session.personaId}</personaid>
    <status>0</status>
    <externalreference>0</externalreference>
    <externaltype>0</externaltype>
  </personadetails>
  <userid>${session.nucleusId}</userid>
</login>`;
    }
    if (command === 'listPersonas' || command === 'list-personas') {
      return `<?xml version="1.0" encoding="UTF-8"?>
<personas>
  <persona>
    <displayname>${session.displayName}</displayname>
    <lastlogin>0</lastlogin>
    <personaid>${session.personaId}</personaid>
    <status>0</status>
    <externalreference>0</externalreference>
    <externaltype>0</externaltype>
  </persona>
</personas>`;
    }
    if (command === 'getAuthToken' || command === 'get-auth-token') {
      return `<?xml version="1.0" encoding="UTF-8"?>\n<authtoken><token>tok_${session.id}</token></authtoken>`;
    }
  }
  
  // Default: empty response
  console.log(`[Main-HTTP] Unhandled: ${path}`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n<response></response>`;
}

function handleCreateAccount(session, pkt) {
  let authToken = 'unknown';
  try {
    const decoded = decodeTdf(pkt.body);
    const authLine = decoded.lines.find(l => l.includes('AUTH'));
    if (authLine) {
      const match = authLine.match(/"([^"]+)"/);
      if (match) authToken = match[1];
    }
  } catch(e) {}
  
  console.log('[CreateAccount] Auth token: ' + authToken);
  session.auth = true;
  
  // Full SessionInfo response matching what PostAuth expects.
  // Key fields: NTOS, PCTK, PRIV, SESS(struct), SPAM, THST, TSUI, TURI
  const enc = new TdfEncoder();
  enc.writeInteger('NTOS', 0);
  enc.writeString('PCTK', '');
  enc.writeString('PRIV', '');
  enc.writeStructStart('SESS');
    enc.writeInteger('BUID', session.nucleusId);
    enc.writeInteger('FRST', 0);
    enc.writeString('KEY ', `sk_${session.id}`);
    enc.writeInteger('LLOG', 0);
    enc.writeString('MAIL', `p${session.id}@fut.local`);
    enc.writeStructStart('PDTL');
      enc.writeString('DSNM', session.displayName);
      enc.writeInteger('LAST', 0);
      enc.writeInteger('PID ', session.personaId);
      enc.writeInteger('STAS', 0);
      enc.writeInteger('XREF', 0);
      enc.writeInteger('XTYP', 0);
    enc.writeStructEnd();
    enc.writeInteger('UID ', session.nucleusId);
  enc.writeStructEnd();
  enc.writeInteger('SPAM', 0);
  enc.writeString('THST', '');
  enc.writeString('TSUI', '');
  enc.writeString('TURI', '');
  
  const body = enc.build();
  console.log('[CreateAccount] Response: ' + body.length + ' bytes (full SessionInfo)');
  return buildReply(pkt, body);
}

function handleFetchClientConfig(pkt) {
  // Decode the CFID from the request
  let cfid = 'unknown';
  try {
    const decoded = decodeTdf(pkt.body);
    const cfidLine = decoded.lines.find(l => l.includes('CFID'));
    if (cfidLine) {
      const match = cfidLine.match(/"([^"]+)"/);
      if (match) cfid = match[1];
    }
  } catch(e) {}
  
  console.log(`[FetchClientConfig] CFID="${cfid}"`);
  
  // Build config map based on the requested config ID
  const enc = new TdfEncoder();
  const configs = {};
  
  if (cfid === 'OSDK_CORE') {
    configs['connIdleTimeout'] = '90s';
    configs['defaultRequestTimeout'] = '60s';
    configs['pingPeriod'] = '15s';
    configs['voipHeadsetUpdateRate'] = '1000';
    configs['xlspConnectionIdleTimeout'] = '300';
  } else if (cfid === 'OSDK_CLIENT') {
    // Client config — version requirements and feature flags
    configs['clientVersion'] = '3175939';
    configs['minimumClientVersion'] = '0';
    configs['updateUrl'] = '';
    configs['forceUpdate'] = '0';
  } else if (cfid === 'OSDK_NUCLEUS') {
    // Nucleus (EA account) config — redirect to our local HTTP server
    configs['nucleusConnect'] = 'http://127.0.0.1:8080';
    configs['nucleusProxy'] = 'http://127.0.0.1:8080';
    configs['nucleusPortal'] = 'http://127.0.0.1:8080';
  } else if (cfid === 'OSDK_WEBOFFER') {
    // Web offer config
    configs['offerUrl'] = 'http://127.0.0.1:8080/offer';
  } else if (cfid === 'OSDK_ABUSE_REPORTING' || cfid === 'OSDK_XMS_ABUSE_REPORTING') {
    // Abuse reporting config
    configs['enabled'] = '0';
  } else if (cfid.includes('DATA')) {
    // Game data config — URLs for services
    configs['GAW_SERVER_BASE_URL'] = 'http://127.0.0.1:8080/';
    configs['IMG_MNGR_BASE_URL'] = 'http://127.0.0.1:8080/content/';
    configs['IMG_MNGR_MAX_BYTES'] = '1048576';
    configs['IMG_MNGR_MAX_IMAGES'] = '5';
    configs['MULTIPLAYER_PROTOCOL_VERSION'] = '3';
    configs['TEL_DISABLE'] = '';
    configs['TEL_DOMAIN'] = 'pc/fifa-2017-pc-anon';
    configs['TEL_FILTER'] = '-UION/****';
    configs['TEL_PORT'] = '9988';
    configs['TEL_SEND_DELAY'] = '15000';
    configs['TEL_SEND_PCT'] = '75';
    configs['TEL_SERVER'] = '127.0.0.1';
  } else if (cfid.includes('MSG') || cfid.includes('msg')) {
    // Messages config — empty
  } else if (cfid.includes('DIME') || cfid.includes('dime')) {
    // DIME (shop) config
    configs['Config'] = '<?xml version="1.0" encoding="UTF-8"?><dime></dime>';
  } else if (cfid.includes('BINI_VERSION') || cfid.includes('bini')) {
    configs['SECTION'] = 'BINI_PC_COMPRESSED';
    configs['VERSION'] = '40128';
  } else if (cfid.includes('ENT') || cfid.includes('ent')) {
    // Entitlements — empty for now
  }
  
  // Always return a CONF map (even if empty)
  enc.writeMap('CONF', configs);
  
  console.log(`[FetchClientConfig] Responding with ${Object.keys(configs).length} config entries`);
  return buildReply(pkt, enc.build());
}

function handlePreAuth(pkt) {
  const variant = process.env.PREAUTH_VARIANT || 'full';
  console.log(`[PreAuth] Variant: ${variant}`);
  
  // Decode and log the request body
  try {
    const decoded = decodeTdf(pkt.body);
    console.log(`[PreAuth] Request TDF:`);
    for (const line of decoded.lines) console.log(`[PreAuth]   ${line}`);
  } catch (e) {
    console.log(`[PreAuth] TDF decode error: ${e.message}`);
  }
  
  if (variant === 'empty' || variant === 'empty_test') {
    // Empty body - tests if the 0xA0 rejection is body-related or header-related
    console.log('[PreAuth] Sending EMPTY response (header-only test)');
    return buildReply(pkt, Buffer.alloc(0));
  }
  
  if (variant === 'noreply') {
    // Test 2: No reply at all - tests if game waits or disconnects on timeout
    console.log('[PreAuth] NOT sending any response');
    return null;
  }
  
  if (variant === 'alt_header') {
    // Obsolete test variant - now using correct 12-byte header
    console.log('[PreAuth] alt_header variant deprecated, using buildReply');
    return buildReply(pkt, Buffer.alloc(0));
  }
  
  if (variant === '12byte') {
    // Test 4: Classic 12-byte header (no 4-byte length prefix)
    console.log('[PreAuth] Sending with 12-byte header (no frame prefix)');
    const enc = new TdfEncoder();
    enc.writeIntList('CIDS', [0x0001, 0x0004, 0x0005, 0x0007, 0x0009, 0x000F, 0x0019, 0x001C, 0x7802]);
    enc.writeStructStart('CONF').writeString('CONF', '{}').writeStructEnd();
    enc.writeString('INST', 'fifa17-fut-server').writeString('NASP', 'cem_ea_id').writeString('PILD', '').writeString('PLAT', 'pc');
    enc.writeStructStart('QOSS').writeStructStart('BWPS').writeString('PSA ', '127.0.0.1').writeInteger('PSP ', 17502).writeString('SNA ', 'prod-sjc').writeStructEnd();
    enc.writeInteger('LNP ', 10).writeTagAndType('LTPS', 0x05);
    // LTPS map: keyType=string(1), valueType=struct(3), count=1
    enc.buffers.push(Buffer.from([0x01, 0x03]));
    enc.buffers.push(enc.encodeVarInt(1));
    const k1 = Buffer.from('bio-dub\0', 'utf-8');
    enc.buffers.push(enc.encodeVarInt(k1.length));
    enc.buffers.push(k1);
    const v1 = new TdfEncoder();
    v1.writeString('PSA ', '127.0.0.1').writeInteger('PSP ', 17502).writeString('SNA ', 'bio-prod-dub-common');
    enc.buffers.push(v1.build());
    enc.buffers.push(Buffer.from([0x00]));
    enc.writeInteger('SVID', 0x45410805).writeStructEnd();
    enc.writeString('RSRC', 'fifa17-2016').writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');
    const body = enc.build();
    // This variant is now the same as buildReply since we fixed the header format
    return buildReply(pkt, body);
  }
  
  // Build PreAuthResponse matching Blaze3SDK schema exactly (14 fields).
  // Schema from zamboni-refs/BlazeSDK/Blaze3SDK/Blaze/Util/PreAuthResponse.cs
  //   ANON, ASRC, CIDS, CNGN, CONF, INST, MINR, NASP, PILD, PLAT, PTAG, QOSS, RSRC, SVER
  // TDF decoder needs fields in alphabetical order by tag.
  const enc = new TdfEncoder();
  enc.writeInteger('ANON', 0);                     // bool: anon child accounts enabled
  enc.writeString('ASRC', '303107');               // auth source
  // CIDS: component IDs — from Blaze3SDK + FIFA 17 additions
  //   Authentication=1, GameManager=4, Redirector=5, Stats=7, Util=9,
  //   CensusData=10, Clubs=11, GameReportingLegacy=12, League=13, Mail=14,
  //   Messaging=15, Playgroups=6, Locker=20, Rooms=21, Tournaments=23,
  //   CommerceInfo=24, AssociationLists=25, GpsContentController=27,
  //   GameReporting=28, DynamicInetFilter=2000, Rsp=2049, UserSessions=30722
  enc.writeIntegerList('CIDS', [1, 4, 5, 7, 9, 10, 11, 12, 13, 14, 15, 20, 21, 25, 27, 28, 2000, 2049, 30722]);
  enc.writeString('CNGN', '');                     // parental consent entitlement group name
  // CONF: nested FetchConfigResponse { CONF: map<string,string> }
  enc.writeStructStart('CONF');
  enc.writeMap('CONF', {
    'connIdleTimeout': '90s',
    'defaultRequestTimeout': '60s',
    'pingPeriod': '15s',
    'voipHeadsetUpdateRate': '1000',
    'xlspConnectionIdleTimeout': '300',
    'nucleusConnect': 'http://127.0.0.1:8080',
    'nucleusProxy': 'http://127.0.0.1:8080',
    'nucleusPortal': 'http://127.0.0.1:8080',
    'identityDisplayUri': 'console2/welcome',
    'identityRedirectUri': 'http://127.0.0.1:8080/success',
    'blazeServerClientId': 'GOS-BlazeServer-FIFA17-PC'
  });
  enc.writeStructEnd();
  enc.writeString('INST', 'fifa-2017-pc-trial');   // instance name — must match client's SVCN
  enc.writeInteger('MINR', 0);                     // bool: underage supported
  enc.writeString('NASP', 'cem_ea_id');            // persona namespace
  enc.writeString('PILD', 'fifa-2017-pc-trial');   // legal doc game identifier (was empty!)
  enc.writeString('PLAT', 'pc');                   // platform
  enc.writeString('PTAG', '');                     // parental consent entitlement tag
  // QOSS: QosConfigInfo { BWPS, LNP, LTPS, SVID }
  enc.writeStructStart('QOSS');
  enc.writeStructStart('BWPS');
  enc.writeString('PSA ', '127.0.0.1');
  enc.writeInteger('PSP ', 17502);
  enc.writeString('SNA ', 'prod-sjc');
  enc.writeStructEnd(); // BWPS
  enc.writeInteger('LNP ', 10);
  // LTPS: Map<string, QosPingSiteInfo> — must have entries for QoS probes to work
  // Each entry: key=site alias, value=struct{PSA(string), PSP(ushort), SNA(string)}
  // Without LTPS entries, the game doesn't send QoS probes and Login job never dispatches
  enc.writeTagAndType('LTPS', 0x05);  // map type
  enc.buffers.push(Buffer.from([0x01, 0x03])); // keyType=string(1), valueType=struct(3)
  enc.buffers.push(enc.encodeVarInt(1));        // 1 entry
  // Key: "bio-dub" (site alias)
  const ltpsKey = Buffer.from('bio-dub\0', 'utf-8');
  enc.buffers.push(enc.encodeVarInt(ltpsKey.length));
  enc.buffers.push(ltpsKey);
  // Value: QosPingSiteInfo struct { PSA, PSP, SNA }
  const ltpsValEnc = new TdfEncoder();
  ltpsValEnc.writeString('PSA ', '127.0.0.1');
  ltpsValEnc.writeInteger('PSP ', 17502);
  ltpsValEnc.writeString('SNA ', 'bio-prod-dub-common');
  const ltpsValBody = ltpsValEnc.build();
  enc.buffers.push(ltpsValBody);
  enc.buffers.push(Buffer.from([0x00])); // struct terminator
  enc.writeInteger('SVID', 0x45410805);
  enc.writeStructEnd(); // QOSS
  enc.writeString('RSRC', '303107');               // registration source
  enc.writeString('SVER', 'Blaze 15.1.2.1.0 (CL# 3175939)');  // server version (no trailing newline)
  // NO PTVR — not in Blaze3SDK schema
  const body = enc.build();
  console.log(`[PreAuth] Sending FIFA17 PreAuth response (${body.length} bytes) — Blaze3SDK schema`);
  return buildReply(pkt, body);
}
function handlePostAuth(session, pkt) {
  const enc = new TdfEncoder();
  enc.writeStructStart('PSS ').writeString('ADRS', '').writeBlob('CSIG', Buffer.alloc(0)).writeString('PJID', '123071').writeInteger('PORT', 443).writeInteger('RPRT', 15).writeInteger('TIID', 0).writeStructEnd();
  enc.writeStructStart('TELE').writeString('ADRS', '127.0.0.1').writeInteger('ANON', 0).writeString('DPTS', 'ut/bf/fifa17').writeInteger('LOCA', 1701729619).writeString('NOOK', '').writeInteger('PORT', 9988).writeInteger('SDLY', 15000).writeString('SESS', 'JMhnT9dXSED').writeString('SKEY', 'key').writeInteger('SPCT', 75).writeString('STIM', '').writeStructEnd();
  enc.writeStructStart('TICK').writeString('ADRS', '').writeInteger('PORT', 0).writeString('SKEY', '').writeStructEnd();
  enc.writeStructStart('UROP').writeInteger('TMOP', 1).writeInteger('UID ', session.nucleusId).writeStructEnd();
  return buildReply(pkt, enc.build());
}
function handleLogin(session, pkt) {
  session.auth = true;
  const enc = new TdfEncoder();
  enc.writeInteger('NTOS', 0).writeString('PCTK', '').writeString('PRIV', '');
  enc.writeStructStart('SESS').writeInteger('BUID', session.nucleusId).writeInteger('FRST', 0).writeString('KEY ', `sk_${session.id}`).writeInteger('LLOG', 0).writeString('MAIL', `p${session.id}@fut.local`);
  enc.writeStructStart('PDTL').writeString('DSNM', session.displayName).writeInteger('LAST', 0).writeInteger('PID ', session.personaId).writeInteger('STAS', 0).writeInteger('XREF', 0).writeInteger('XTYP', 0).writeStructEnd();
  enc.writeInteger('UID ', session.nucleusId).writeStructEnd();
  enc.writeInteger('SPAM', 0).writeString('THST', '').writeString('TSUI', '').writeString('TURI', '');
  return buildReply(pkt, enc.build());
}
function handleListPersona(session, pkt) {
  const enc = new TdfEncoder();
  enc.writeList('PLST', 0x03, 1, (e) => { e.writeString('DSNM', session.displayName).writeInteger('LAST', 0).writeInteger('PID ', session.personaId).writeInteger('STAS', 0).writeInteger('XREF', 0).writeInteger('XTYP', 0); });
  return buildReply(pkt, enc.build());
}
function handlePing(pkt) { return buildReply(pkt, new TdfEncoder().writeInteger('STIM', BigInt(Date.now())).build()); }
function handleGetTelemetry(pkt) {
  const enc = new TdfEncoder();
  enc.writeString('ADRS', '127.0.0.1').writeInteger('ANON', 0).writeString('DPTS', 'ut/bf/fifa17').writeInteger('LOCA', 1701729619).writeString('NOOK', '').writeInteger('PORT', 9988).writeInteger('SDLY', 15000).writeString('SESS', '').writeString('SKEY', '').writeInteger('SPCT', 75).writeString('STIM', '');
  return buildReply(pkt, enc.build());
}

// ============================================================
// HTTP Server
// ============================================================
function startHttpServer() {
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      console.log(`[HTTP] ${req.method} ${req.url}`);
      if (body) console.log(`[HTTP] Body: ${body.substring(0, 500)}`);
      
      // Nucleus API handlers for OSDK account creation flow
      const url = req.url || '';
      
      if (url.includes('/connect/token')) {
        // OAuth token exchange — game sends auth code, we return access token
        console.log('[HTTP-NUCLEUS] Token exchange request');
        console.log(`[HTTP-NUCLEUS] Body: ${body}`);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ 
          access_token: 'fake_access_token_12345', 
          token_type: 'Bearer', 
          expires_in: 3600,
          refresh_token: 'fake_refresh_12345'
        }));
      } else if (url.includes('/connect/auth')) {
        // OAuth authorize — redirect with auth code
        console.log('[HTTP-NUCLEUS] OAuth authorize');
        const redirectMatch = url.match(/redirect_uri=([^&]+)/);
        const redirectUri = redirectMatch ? decodeURIComponent(redirectMatch[1]) : '/callback';
        console.log(`[HTTP-NUCLEUS] Redirecting to: ${redirectUri}`);
        res.writeHead(302, { 'Location': `${redirectUri}?code=FAKE_AUTH_CODE_12345` });
        res.end();
      } else if (url.includes('/identity/pids/me/personas')) {
        console.log('[HTTP-NUCLEUS] List personas');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ personas: { persona: [{ personaId: 1000000001, pidId: 2000000001, displayName: 'Player1', namespaceName: 'cem_ea_id', isVisible: true, status: 'ACTIVE' }] } }));
      } else if (url.includes('/identity/pids')) {
        console.log('[HTTP-NUCLEUS] PID request');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ pid: { pidId: 2000000001, email: 'player@fut.local', dob: '1990-01-01', status: 'ACTIVE', country: 'US', displayName: 'Player1' } }));
      } else if (url.includes('/proxy/identity')) {
        console.log('[HTTP-NUCLEUS] Proxy identity');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ pid: { pidId: 2000000001, displayName: 'Player1' } }));
      } else {
        // CATCH-ALL: Log everything and serve HTML for web view requests
        console.log(`[HTTP] *** CATCH-ALL: ${req.method} ${url} ***`);
        console.log(`[HTTP] Headers: ${JSON.stringify(req.headers).substring(0, 500)}`);
        if (body) console.log(`[HTTP] Body: ${body.substring(0, 500)}`);
        
        // Check if this looks like a browser/web view request
        const accept = req.headers['accept'] || '';
        if (accept.includes('text/html') || !accept.includes('json')) {
          // Serve HTML page for the OSDK web view
          res.setHeader('Content-Type', 'text/html');
          res.end(`<!DOCTYPE html>
<html><head><title>EA Account</title></head>
<body>
<h2>Account Created Successfully</h2>
<p>Your FIFA 17 account has been set up. Redirecting...</p>
<script>
// Auto-redirect with auth code after 500ms
setTimeout(function() {
  window.location.href = '/callback?code=FAKE_AUTH_CODE_12345&state=done';
}, 500);
</script>
</body></html>`);
        } else {
          res.setHeader('Content-Type', 'application/json');
          res.end('{"status":"ok"}');
        }
      }
    });
  }).listen(HTTP_PORT, '0.0.0.0', () => console.log(`[HTTP] on port ${HTTP_PORT}`));
}

// ============================================================
// Start
// ============================================================
console.log('=== FIFA 17 FUT Private Server ===\n');
// Clear log file at startup
try { fs.writeFileSync(path.join(repoRoot, 'batch-results.log'), '', 'utf8'); } catch(e) {}
startRedirector();
startMainServer();
startHttpServer();

// HTTPS QoS server on port 17502
// The game sends HTTPS requests to https://<BWPS_address>:<BWPS_port>/qos/firewall
// and /qos/firetype during the Login job's QoS phase.
// Without valid responses, the Login job never dispatches the Login RPC.
import https from 'https';
// Load certs — try multiple paths since .pem files may not be in git
let qosKeyData, qosCertData;
for (const pair of [['server2048.key','server2048_sha1.crt'],['server.key','server.crt'],['key.pem','cert.pem']]) {
  try {
    qosKeyData = fs.readFileSync(path.join(__dirname, pair[0]));
    qosCertData = fs.readFileSync(path.join(__dirname, pair[1]));
    console.log(`[QOS-HTTPS] Using certs: ${pair[0]} + ${pair[1]}`);
    break;
  } catch(e) {}
}
if (!qosKeyData) {
  // Generate self-signed cert at runtime using openssl
  console.log('[QOS-HTTPS] No cert files found — generating self-signed cert');
  try {
    execSync('openssl req -x509 -newkey rsa:2048 -keyout qos_key.pem -out qos_cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"', { cwd: __dirname, stdio: 'ignore' });
    qosKeyData = fs.readFileSync(path.join(__dirname, 'qos_key.pem'));
    qosCertData = fs.readFileSync(path.join(__dirname, 'qos_cert.pem'));
    console.log('[QOS-HTTPS] Generated qos_key.pem + qos_cert.pem');
  } catch(e) {
    console.log('[QOS-HTTPS] openssl not available — QoS HTTPS server disabled');
    console.log('[QOS-HTTPS] Error: ' + e.message);
  }
}
if (qosKeyData && qosCertData) {
const qosHttpsServer = https.createServer({
  key: qosKeyData, cert: qosCertData, rejectUnauthorized: false,
}, (req, res) => {
  console.log(`[QOS-HTTPS] ${req.method} ${req.url}`);
  
  if (req.url.includes('/qos/firewall')) {
    console.log('[QOS-HTTPS] Firewall check — responding OK');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else if (req.url.includes('/qos/firetype')) {
    console.log('[QOS-HTTPS] Firetype check — responding OK');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else {
    console.log(`[QOS-HTTPS] Unknown request: ${req.url}`);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  }
});
qosHttpsServer.on('error', (err) => console.log(`[QOS-HTTPS] Error: ${err.message}`));
qosHttpsServer.listen(17502, '0.0.0.0', () => console.log('[QOS-HTTPS] Listening on HTTPS port 17502'));
} else {
  console.log('[QOS-HTTPS] QoS HTTPS server disabled (no certs)');
}

// Also keep UDP QoS server as fallback
import dgram from 'dgram';
const qosServer = dgram.createSocket('udp4');
qosServer.on('message', (msg, rinfo) => {
  console.log(`[QOS-UDP] Received ${msg.length} bytes from ${rinfo.address}:${rinfo.port}`);
  qosServer.send(msg, rinfo.port, rinfo.address);
});
qosServer.on('error', (err) => console.log(`[QOS-UDP] Error: ${err.message}`));
qosServer.bind(17503, '0.0.0.0', () => console.log('[QOS-UDP] Listening on UDP port 17503'));

// Also revert CreateAccount to success response (error 0x0F didn't help)
// and restore Logout response (ignoring didn't help — game disconnects anyway)

// Catch-all listeners on common ports to detect where the game connects next
[443, 9988, 80, 9946].forEach(port => {
  if (port === HTTP_PORT || port === MAIN_BLAZE_PORT || port === REDIRECTOR_PORT) return;
  net.createServer((socket) => {
    console.log(`[PORT-${port}] Connection from ${socket.remoteAddress}:${socket.remotePort}`);
    let buf = Buffer.alloc(0);
    socket.on('data', (data) => {
      buf = Buffer.concat([buf, data]);
      const hex = Array.from(data.subarray(0, Math.min(64, data.length))).map(b => b.toString(16).padStart(2,'0')).join(' ');
      const ascii = data.toString('ascii', 0, Math.min(64, data.length)).replace(/[^\x20-\x7e]/g, '.');
      console.log(`[PORT-${port}] ${data.length} bytes: ${hex}`);
      console.log(`[PORT-${port}] ASCII: ${ascii}`);
    });
    socket.on('close', () => console.log(`[PORT-${port}] Disconnected`));
    socket.on('error', (e) => console.log(`[PORT-${port}] Error: ${e.message}`));
  }).listen(port, '0.0.0.0', () => console.log(`[Catch] Listening on port ${port}`)).on('error', (e) => {
    console.log(`[Catch] Cannot listen on port ${port}: ${e.message}`);
  });
});

console.log('\nWaiting for FIFA 17...');
console.log('hosts: 127.0.0.1 winter15.gosredirector.ea.com\n');

