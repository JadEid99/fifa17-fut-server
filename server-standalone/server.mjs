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
    if (v < 0n) { v = -v; bytes.push(Number(v & 0x3Fn) | 0x80); v >>= 6n; }
    else { bytes.push(Number(v & 0x3Fn)); v >>= 6n; }
    while (v > 0n) { bytes[bytes.length - 1] |= 0x40; bytes.push(Number(v & 0x7Fn)); v >>= 7n; }
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
  build() { return Buffer.concat(this.buffers); }
}

// ============================================================
// Blaze Packet Codec
// ============================================================

const HEADER_SIZE = 12;
function decodeHeader(buf) {
  if (buf.length < HEADER_SIZE) return null;
  return { length: buf.readUInt16BE(0), component: buf.readUInt16BE(2), command: buf.readUInt16BE(4), error: buf.readUInt16BE(6), msgType: (buf.readUInt32BE(8) >> 16) & 0xF000, msgId: buf.readUInt32BE(8) & 0xFFFF };
}
function encodeHeader(h) {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt16BE(h.length, 0); buf.writeUInt16BE(h.component, 2); buf.writeUInt16BE(h.command, 4); buf.writeUInt16BE(h.error, 6);
  buf.writeUInt32BE(((h.msgType & 0xF000) << 16) | (h.msgId & 0xFFFF), 8);
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
  const recordVersion = [0x03, 0x00]; // SSLv3 record layer
  const replyVersion = [0x03, 0x00]; // SSLv3 in ServerHello body

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

  // Server cert with Aim4kill ProtoSSL bug applied:
  // The algorithmIdentifier (2nd occurrence of sig OID) is patched from
  // SHA1withRSA (..01 05) to RSA_PKCS_KEY (..01 01). This makes ProtoSSL
  // hit the default case, set iHashSize=0, and memcmp(x,y,0)==0 always.
  const certDerB64 = 'MIICrTCCAhYCFEPuJkoJqIs+1Hc7CaSyYdNeUYDTMA0GCSqGSIb3DQEBBQUAMIGgMSAwHgYDVQQLDBdPbmxpbmUgVGVjaG5vbG9neSBHcm91cDEeMBwGA1UECgwVRWxlY3Ryb25pYyBBcnRzLCBJbmMuMRUwEwYDVQQHDAxSZWR3b29kIENpdHkxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMSMwIQYDVQQDDBpPVEczIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0yNjA0MTAxMjUzNTVaFw01MzA4MjYxMjUzNTVaMIGJMSYwJAYDVQQDDB13aW50ZXIxNS5nb3NyZWRpcmVjdG9yLmVhLmNvbTEdMBsGA1UECwwUR2xvYmFsIE9ubGluZSBTdHVkaW8xHjAcBgNVBAoMFUVsZWN0cm9uaWMgQXJ0cywgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK4Jk1ombSA0y8N7G5RO4GyclW4dEp6E3GwvS2kKnyLgSHarNqj6qY4f06sX+U+4i6Uqz7ukxFFAyormGJKDZxPMCAYO48lHTsbGhvRIimCePpqxMTGOxbBw63TvZfOWdFGNJwSnA8Hzqu8FmEW3qAwX9ZjUCrTaFowYC60L09V3AgMBAAEwDQYJKoZIhvcNAQEBBQADgYEAE4v8rraydetF9oMcQ403Pm3Dz2k/ZXklQtt3pz3o/Hx1GH8kFIdMMoucCiQTyxOF97K32x96LI+CKzYgX15WehvtNGZUALHFdBpYTFIEVbnOijBsHqcKS3bn6P75znZTgRRzJJO4GV0cDKa6DZyPJraz7wvPD92RVplAgrWiUPw=';
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

  socket.removeAllListeners('data');
  socket.on('data', (data) => {
    pendingBuf = Buffer.concat([pendingBuf, data]);
    console.log(`[SSL] Phase=${phase}, received ${data.length} bytes`);

    // Hex dump
    for (let i = 0; i < Math.min(data.length, 256); i += 16) {
      const slice = data.subarray(i, Math.min(i + 16, data.length));
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
      console.log(`  ${i.toString(16).padStart(4, '0')}: ${hex}`);
    }

    if (phase === 'waiting_client_response') {
      // Parse records from the client
      let offset = 0;
      while (offset + 5 <= pendingBuf.length) {
        const recType = pendingBuf[offset];
        const recVer = (pendingBuf[offset + 1] << 8) | pendingBuf[offset + 2];
        const recLen = (pendingBuf[offset + 3] << 8) | pendingBuf[offset + 4];
        
        if (offset + 5 + recLen > pendingBuf.length) break; // incomplete record
        
        const recBody = pendingBuf.subarray(offset + 5, offset + 5 + recLen);
        console.log(`[SSL] Record: type=0x${recType.toString(16)} ver=0x${recVer.toString(16)} len=${recLen}`);

        if (recType === 0x16) {
          // Handshake record
          const hsType = recBody[0];
          console.log(`[SSL] Handshake type: 0x${hsType.toString(16)} (${hsType === 0x10 ? 'ClientKeyExchange' : hsType === 0x14 ? 'Finished' : 'unknown'})`);
          
          if (hsType === 0x10) {
            // ClientKeyExchange - contains encrypted pre-master secret
            const pmsLen = (recBody[1] << 16) | (recBody[2] << 8) | recBody[3];
            // In TLS, there's a 2-byte length prefix for the encrypted PMS
            let encPMS;
            if (recBody.length > 4 + 2) {
              const explicitLen = (recBody[4] << 8) | recBody[5];
              encPMS = recBody.subarray(6, 6 + explicitLen);
            } else {
              encPMS = recBody.subarray(4);
            }
            console.log(`[SSL] Encrypted pre-master secret: ${encPMS.length} bytes`);

            // Decrypt pre-master secret with our private key
            try {
              const preMasterSecret = crypto.privateDecrypt(
                { key: keyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
                encPMS
              );
              console.log(`[SSL] Decrypted pre-master secret: ${preMasterSecret.length} bytes, version=0x${preMasterSecret.readUInt16BE(0).toString(16)}`);

              // Derive master secret and keys
              const keys = deriveKeys(preMasterSecret, clientRandom, serverRandom, selectedCipher);
              console.log(`[SSL] Master secret derived, keys ready`);

              // Store keys for later use
              socket._sslKeys = keys;
              socket._selectedCipher = selectedCipher;
              socket._serverRandom = serverRandom;
              socket._clientRandom = clientRandom;
              socket._allHS = allHandshakeMessages;
              socket._allHS.push(recBody); // add ClientKeyExchange
            } catch (e) {
              console.log(`[SSL] Failed to decrypt pre-master secret: ${e.message}`);
            }
          }
        } else if (recType === 0x14) {
          // ChangeCipherSpec
          console.log('[SSL] Client ChangeCipherSpec received');
        } else if (recType === 0x16 && recBody[0] === 0x14) {
          // This shouldn't happen in plaintext after CCS
        }

        offset += 5 + recLen;
      }
      pendingBuf = pendingBuf.subarray(offset);

      // If we have keys, send our ChangeCipherSpec + Finished
      if (socket._sslKeys) {
        // Send ChangeCipherSpec
        socket.write(wrapRecord(0x14, recordVersion, Buffer.from([0x01])));
        console.log('[SSL] Sent ChangeCipherSpec');

        // For now, send an encrypted Finished message
        // The Finished verify_data is PRF(master_secret, "server finished", Hash(all_handshake_messages))
        const keys = socket._sslKeys;
        
        // Build Finished message
        const allHSBuf = Buffer.concat(socket._allHS);
        const verifyData = tlsPRF(keys.masterSecret, 'server finished', 
          Buffer.concat([
            crypto.createHash('md5').update(allHSBuf).digest(),
            crypto.createHash('sha1').update(allHSBuf).digest()
          ]), 12);
        
        const finishedMsg = wrapHandshake(0x14, verifyData);
        
        // Encrypt the Finished message
        const encrypted = encryptRecord(0x16, recordVersion, finishedMsg, keys.serverWriteKey, keys.serverWriteMAC, keys, selectedCipher);
        socket.write(encrypted);
        console.log('[SSL] Sent encrypted Finished');

        phase = 'established';
        
        // Set up decryption for incoming data
        socket._readSeqNum = BigInt(1); // after Finished
        socket._writeSeqNum = BigInt(1);
        
        // Now handle decrypted Blaze packets
        socket.removeAllListeners('data');
        setupEncryptedBlazeHandler(socket, keys, selectedCipher);
      }
    }
  });

  // NOW send the handshake messages (listener is already set up above)
  const serverHelloRecord = wrapRecord(0x16, recordVersion, serverHelloMsg);
  const certRecord = wrapRecord(0x16, recordVersion, certMsg);
  const helloDoneRecord = wrapRecord(0x16, recordVersion, helloDoneMsg);
  
  console.log(`[SSL] Sending ServerHello (${serverHelloRecord.length}b) + Certificate (${certRecord.length}b) + ServerHelloDone (${helloDoneRecord.length}b)`);
  socket.write(Buffer.concat([serverHelloRecord, certRecord, helloDoneRecord]));
  console.log(`[SSL] Sent all handshake messages. Waiting for ClientKeyExchange...`);
}

// TLS PRF (Pseudo-Random Function) for TLS 1.0/1.1
function tlsPRF(secret, label, seed, length) {
  const labelBuf = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBuf, seed]);
  
  // Split secret in half
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
  let a = seed; // A(0) = seed
  while (Buffer.concat(output).length < length) {
    a = crypto.createHmac(algo, secret).update(a).digest(); // A(i)
    output.push(crypto.createHmac(algo, secret).update(Buffer.concat([a, seed])).digest());
  }
  return Buffer.concat(output).subarray(0, length);
}

function deriveKeys(preMasterSecret, clientRandom, serverRandom, cipher) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  const masterSecret = tlsPRF(preMasterSecret, 'master secret', seed, 48);
  
  const keySeed = Buffer.concat([serverRandom, clientRandom]);
  // For RC4-128-SHA: MAC=20, Key=16, IV=0
  // For AES-128-CBC-SHA: MAC=20, Key=16, IV=16
  let macLen = 20, keyLen = 16, ivLen = 0;
  if (cipher === 0x002f) ivLen = 16; // AES-128-CBC
  if (cipher === 0x0035) { keyLen = 32; ivLen = 16; } // AES-256-CBC
  
  const totalNeeded = 2 * macLen + 2 * keyLen + 2 * ivLen;
  const keyBlock = tlsPRF(masterSecret, 'key expansion', keySeed, totalNeeded);
  
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
  // Compute MAC: HMAC-SHA1(mac_key, seq_num + type + version + length + data)
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

function setupEncryptedBlazeHandler(socket, keys, cipher) {
  let pendingBuf = Buffer.alloc(0);
  let blazeBuf = Buffer.alloc(0);

  socket.on('data', (data) => {
    pendingBuf = Buffer.concat([pendingBuf, data]);

    // Parse TLS records
    while (pendingBuf.length >= 5) {
      const recType = pendingBuf[0];
      const recLen = (pendingBuf[3] << 8) | pendingBuf[4];
      if (pendingBuf.length < 5 + recLen) break;

      const recBody = pendingBuf.subarray(5, 5 + recLen);
      pendingBuf = pendingBuf.subarray(5 + recLen);

      if (recType === 0x17) {
        // Application data - decrypt it
        try {
          const plaintext = decryptRecord(0x17, [0x03, 0x03], recBody, keys.clientWriteKey, keys.clientWriteMAC, keys, cipher);
          console.log(`[SSL] Decrypted ${plaintext.length} bytes of application data`);
          
          // Feed into Blaze packet parser
          blazeBuf = Buffer.concat([blazeBuf, plaintext]);
          let result = readPacket(blazeBuf);
          while (result) {
            blazeBuf = result.remaining;
            const pkt = result.packet;
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
              const reply = buildReply(pkt, enc.build());
              
              // Encrypt and send
              const encReply = encryptRecord(0x17, [0x03, 0x03], reply, keys.serverWriteKey, keys.serverWriteMAC, keys, cipher);
              socket.write(encReply);
              console.log('[Redirector] Sent encrypted redirect response');
              setTimeout(() => socket.end(), 100);
            }
            result = readPacket(blazeBuf);
          }
        } catch (e) {
          console.log(`[SSL] Decryption error: ${e.message}`);
        }
      } else if (recType === 0x15) {
        console.log('[SSL] Alert received');
      }
    }
  });
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

    handleBlazeStream(socket, `Main:${sid}`, (pkt) => {
      const { component: comp, command: cmd } = pkt.header;
      console.log(`[Main] S${sid}: comp=0x${comp.toString(16).padStart(4,'0')} cmd=0x${cmd.toString(16).padStart(4,'0')}`);
      let resp = null;
      if (comp === 0x0009) {
        if (cmd === 0x0007) resp = handlePreAuth(pkt);
        else if (cmd === 0x0008) resp = handlePostAuth(session, pkt);
        else if (cmd === 0x0002) resp = handlePing(pkt);
        else if (cmd === 0x0003) resp = handleGetTelemetry(pkt);
        else if (cmd === 0x0001) resp = buildReply(pkt, new TdfEncoder().build());
        else if (cmd === 0x000B) resp = buildReply(pkt, new TdfEncoder().writeString('SVAL', '').build());
        else resp = buildReply(pkt, Buffer.alloc(0));
      } else if (comp === 0x0001) {
        if ([0x0028, 0x00C8, 0x0032, 0x003C].includes(cmd)) resp = handleLogin(session, pkt);
        else if (cmd === 0x001D) resp = buildReply(pkt, new TdfEncoder().build());
        else if (cmd === 0x0024) resp = buildReply(pkt, new TdfEncoder().writeString('AUTH', `tok_${sid}`).build());
        else if (cmd === 0x0030) resp = handleListPersona(session, pkt);
        else if (cmd === 0x002A) resp = buildReply(pkt, new TdfEncoder().writeInteger('TOSI', 0).build());
        else resp = buildReply(pkt, Buffer.alloc(0));
      } else if (comp === 0x7802) { resp = buildReply(pkt, Buffer.alloc(0)); }
      else { console.log(`[Main] Unhandled comp=0x${comp.toString(16)} cmd=0x${cmd.toString(16)}`); resp = buildReply(pkt, Buffer.alloc(0)); }
      if (resp) socket.write(resp);
    });
    socket.on('close', () => console.log(`[Main] S${sid} disconnected`));
    socket.on('error', (e) => console.log(`[Main] S${sid} error: ${e.message}`));
  });
  server.listen(MAIN_BLAZE_PORT, '0.0.0.0', () => console.log(`[Main] Blaze server on port ${MAIN_BLAZE_PORT}`));
}

function handlePreAuth(pkt) {
  const enc = new TdfEncoder();
  enc.writeIntList('CIDS', [0x0001, 0x0004, 0x0005, 0x0007, 0x0009, 0x000F, 0x0019, 0x001C, 0x7802]);
  enc.writeStructStart('CONF').writeString('CONF', '{}').writeStructEnd();
  enc.writeString('INST', 'fifa17-fut-server').writeString('NASP', 'cem_ea_id').writeString('PILD', '').writeString('PLAT', 'pc');
  enc.writeStructStart('QOSS').writeStructStart('BWPS').writeString('PSA ', '127.0.0.1').writeInteger('PSP ', 17502).writeString('SNA ', 'prod-sjc').writeStructEnd();
  enc.writeInteger('LNP ', 10).writeStructStart('LTPS').writeStructEnd().writeInteger('SVID', 0x45410805).writeStructEnd();
  enc.writeString('RSRC', 'fifa17-2016').writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');
  return buildReply(pkt, enc.build());
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
console.log('\nWaiting for FIFA 17...');
console.log('hosts: 127.0.0.1 winter15.gosredirector.ea.com\n');
