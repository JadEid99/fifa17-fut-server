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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

const HEADER_SIZE = 16;
function decodeHeader(buf) {
  if (buf.length < HEADER_SIZE) return null;
  // Fire2 frame format: [4-byte payload length] [12-byte Blaze header]
  // The 12-byte Blaze header at offset 4:
  //   [4-5]   uint16 secondary length/flags (often 0 or same as component high bits)
  //   [6-7]   uint16 component
  //   [8-9]   uint16 command
  //   [10-11] uint16 error
  //   [12-15] uint32 msgType(upper 16) + msgId(lower 16)
  const length = buf.readUInt32BE(0);
  const component = buf.readUInt16BE(6);
  const command = buf.readUInt16BE(8);
  const error = buf.readUInt16BE(10);
  const msgTypeAndId = buf.readUInt32BE(12);
  const msgType = (msgTypeAndId >>> 16) & 0xFFFF;
  const msgId = msgTypeAndId & 0xFFFF;
  return { length, component, command, error, msgType, msgId };
}
function encodeHeader(h) {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt32BE(h.length, 0);           // payload length
  buf.writeUInt16BE(0, 4);                  // padding/flags
  buf.writeUInt16BE(h.component, 6);        // component
  buf.writeUInt16BE(h.command, 8);          // command
  buf.writeUInt16BE(h.error, 10);           // error
  // Pack msgType into upper 16 bits, msgId into lower 16 bits
  const msgTypeAndId = ((h.msgType & 0xFFFF) << 16) | ((h.msgId || 0) & 0xFFFF);
  buf.writeUInt32BE(msgTypeAndId >>> 0, 12);
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
  const h = encodeHeader({ length: body.length, component: req.header.component, command: req.header.command, error, msgType: error ? 0x3000 : 0x1000, msgId: req.header.msgId });
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
              console.log(`[Blaze-Enc] comp=0x${pkt.header.component.toString(16).padStart(4,'0')} cmd=0x${pkt.header.command.toString(16).padStart(4,'0')} len=${pkt.header.length}`);
              const resp = handleBlazePacket(pkt);
              if (resp) {
                const encReply = encryptRecord(0x17, [0x03, 0x03], resp, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
                socket.write(encReply);
                console.log(`[Blaze-Enc] Sent encrypted reply (${resp.length} bytes)`);
                // Hex dump the response for debugging
                for (let i = 0; i < resp.length; i += 16) {
                  const slice = resp.subarray(i, Math.min(i + 16, resp.length));
                  const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
                  console.log(`[Blaze-Enc]   ${i.toString(16).padStart(4,'0')}: ${hex}`);
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
    pendingBuf = Buffer.concat([pendingBuf, data]);
    processPending();
  });

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
    const secure = process.env.REDIRECT_SECURE || '1';
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
    socket.on('close', () => console.log(`[Main] S${sid} disconnected`));
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
      if (comp === 0x0009) {
        if (cmd === 0x0007) { console.log(`[Main] S${sid}: -> PreAuth`); resp = handlePreAuth(pkt); }
        else if (cmd === 0x0008) { console.log(`[Main] S${sid}: -> PostAuth`); resp = handlePostAuth(session, pkt); }
        else if (cmd === 0x0002) resp = handlePing(pkt);
        else if (cmd === 0x0003) resp = handleGetTelemetry(pkt);
        else if (cmd === 0x0001) resp = buildReply(pkt, new TdfEncoder().build());
        else if (cmd === 0x000B) resp = buildReply(pkt, new TdfEncoder().writeString('SVAL', '').build());
        else { console.log(`[Main] S${sid}: -> Util unknown cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      } else if (comp === 0x0001) {
        if ([0x0028, 0x00C8, 0x0032, 0x003C].includes(cmd)) { console.log(`[Main] S${sid}: -> Login`); resp = handleLogin(session, pkt); }
        else if (cmd === 0x001D) resp = buildReply(pkt, new TdfEncoder().build());
        else if (cmd === 0x0024) resp = buildReply(pkt, new TdfEncoder().writeString('AUTH', `tok_${sid}`).build());
        else if (cmd === 0x0030) { console.log(`[Main] S${sid}: -> ListPersonas`); resp = handleListPersona(session, pkt); }
        else if (cmd === 0x002A) resp = buildReply(pkt, new TdfEncoder().writeInteger('TOSI', 0).build());
        else { console.log(`[Main] S${sid}: -> Auth unknown cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      } else if (comp === 0x7802) { resp = buildReply(pkt, Buffer.alloc(0)); }
      else { console.log(`[Main] S${sid}: -> Unhandled comp=0x${comp.toString(16)} cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      if (resp) {
        console.log(`[Main] S${sid}: Sending response (${resp.length} bytes)`);
        const hdrHex = Array.from(resp.subarray(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`[Main] S${sid}: Response header: ${hdrHex}`);
        socket.write(resp);
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
  
  if (variant === 'empty') {
    // Test 1: Empty body - tests if header format is OK
    console.log('[PreAuth] Sending empty response');
    return buildReply(pkt, Buffer.alloc(0));
  }
  
  if (variant === 'noreply') {
    // Test 2: No reply at all - tests if game waits or disconnects on timeout
    console.log('[PreAuth] NOT sending any response');
    return null;
  }
  
  if (variant === 'alt_header') {
    // Test 3: Alternative header - msgType at offset 4 instead of 12
    console.log('[PreAuth] Sending with alt header (msgType at offset 4)');
    const enc = new TdfEncoder();
    enc.writeIntList('CIDS', [0x0001, 0x0004, 0x0005, 0x0007, 0x0009, 0x000F, 0x0019, 0x001C, 0x7802]);
    enc.writeStructStart('CONF').writeString('CONF', '{}').writeStructEnd();
    enc.writeString('INST', 'fifa17-fut-server').writeString('NASP', 'cem_ea_id').writeString('PILD', '').writeString('PLAT', 'pc');
    enc.writeStructStart('QOSS').writeStructStart('BWPS').writeString('PSA ', '127.0.0.1').writeInteger('PSP ', 17502).writeString('SNA ', 'prod-sjc').writeStructEnd();
    enc.writeInteger('LNP ', 10).writeStructStart('LTPS').writeStructEnd().writeInteger('SVID', 0x45410805).writeStructEnd();
    enc.writeString('RSRC', 'fifa17-2016').writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');
    const body = enc.build();
    // Build header manually with msgType at offset 4
    const hdr = Buffer.alloc(16);
    hdr.writeUInt32BE(body.length, 0);
    hdr.writeUInt16BE(0x1000, 4);  // msgType at offset 4
    hdr.writeUInt16BE(pkt.header.component, 6);
    hdr.writeUInt16BE(pkt.header.command, 8);
    hdr.writeUInt16BE(0, 10);
    hdr.writeUInt32BE(pkt.header.msgId || 0, 12);  // msgId at offset 12
    return Buffer.concat([hdr, body]);
  }
  
  if (variant === '12byte') {
    // Test 4: Classic 12-byte header (no 4-byte length prefix)
    console.log('[PreAuth] Sending with 12-byte header (no frame prefix)');
    const enc = new TdfEncoder();
    enc.writeIntList('CIDS', [0x0001, 0x0004, 0x0005, 0x0007, 0x0009, 0x000F, 0x0019, 0x001C, 0x7802]);
    enc.writeStructStart('CONF').writeString('CONF', '{}').writeStructEnd();
    enc.writeString('INST', 'fifa17-fut-server').writeString('NASP', 'cem_ea_id').writeString('PILD', '').writeString('PLAT', 'pc');
    enc.writeStructStart('QOSS').writeStructStart('BWPS').writeString('PSA ', '127.0.0.1').writeInteger('PSP ', 17502).writeString('SNA ', 'prod-sjc').writeStructEnd();
    enc.writeInteger('LNP ', 10).writeStructStart('LTPS').writeStructEnd().writeInteger('SVID', 0x45410805).writeStructEnd();
    enc.writeString('RSRC', 'fifa17-2016').writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');
    const body = enc.build();
    // Classic 12-byte Blaze header
    const hdr = Buffer.alloc(12);
    hdr.writeUInt16BE(body.length, 0);
    hdr.writeUInt16BE(pkt.header.component, 2);
    hdr.writeUInt16BE(pkt.header.command, 4);
    hdr.writeUInt16BE(0, 6);
    hdr.writeUInt32BE(0x10000000 | (pkt.header.msgId || 0), 8);
    return Buffer.concat([hdr, body]);
  }
  
  // Default: minimal response matching PocketRelay structure
  const enc = new TdfEncoder();
  enc.writeIntList('CIDS', [1, 4, 7, 9, 25, 28, 30722]);
  enc.writeStructStart('CONF');
  enc.writeMap('CONF', {
    'connIdleTimeout': '90s',
    'defaultRequestTimeout': '60s',
    'nucleusConnect': 'https://accounts.ea.com',
    'nucleusProxy': 'https://gateway.ea.com',
    'pingPeriod': '15s',
    'voipHeadsetUpdateRate': '1000',
    'xlspConnectionIdleTimeout': '300'
  });
  enc.writeStructEnd();
  enc.writeString('INST', 'fifa17-2016');
  enc.writeString('NASP', 'cem_ea_id');
  enc.writeString('PILD', '');
  enc.writeString('PLAT', 'pc');
  enc.writeStructStart('QOSS');
  enc.writeStructStart('BWPS');
  enc.writeString('PSA ', '127.0.0.1');
  enc.writeInteger('PSP ', 17502);
  enc.writeString('SNA ', 'prod-sjc');
  enc.writeStructEnd();
  enc.writeInteger('LNP ', 10);
  enc.writeStructStart('LTPS');
  enc.writeStructEnd();
  enc.writeInteger('SVID', 0x45410805);
  enc.writeStructEnd();
  enc.writeString('RSRC', 'fifa17-2016');
  enc.writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');
  const body = enc.build();
  // Verify our own TDF is decodable
  try {
    const selfDecode = decodeTdf(body);
    console.log(`[PreAuth] Response TDF self-decode:`);
    for (const line of selfDecode.lines) console.log(`[PreAuth]   ${line}`);
  } catch (e) {
    console.log(`[PreAuth] Response TDF self-decode FAILED: ${e.message}`);
  }
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
    console.log(`[HTTP] ${req.method} ${req.url}`);
    res.setHeader('Content-Type', 'application/json');
    res.end('{"status":"ok"}');
  }).listen(HTTP_PORT, '0.0.0.0', () => console.log(`[HTTP] on port ${HTTP_PORT}`));
}

// ============================================================
// Start
// ============================================================
console.log('=== FIFA 17 FUT Private Server ===\n');
startRedirector();
startMainServer();
startHttpServer();

// Catch-all listeners on common ports to detect where the game connects next
[443, 9988, 17502, 80, 9946].forEach(port => {
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

