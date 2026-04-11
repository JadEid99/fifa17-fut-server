/**
 * Blaze Redirector Server
 * 
 * This is the first server FIFA 17 contacts. It connects to
 * winter15.gosredirector.ea.com:42230 and asks "where is the main server?"
 * 
 * We respond with our own server's address so the game connects to us.
 * 
 * The redirector uses EA's custom SSLv3 implementation. For our purposes,
 * we'll first try without SSL to see if the game falls back, and if not,
 * we'll need to handle the SSL handshake.
 */

import * as net from 'net';
import * as tls from 'tls';
import * as fs from 'fs';
import * as path from 'path';
import { BlazeComponent, BlazePacket, MessageType, RedirectorCommand } from './types.js';
import { buildReply, readPacket } from './codec.js';
import { TdfEncoder } from './tdf.js';

const REDIRECTOR_PORT = 42230;

interface RedirectorConfig {
  // The IP/hostname of our main Blaze server
  targetHost: string;
  // The port of our main Blaze server
  targetPort: number;
}

/**
 * Build the response body for a GetServerInstance request.
 * This tells the game client where to find the main Blaze server.
 */
function buildServerInstanceResponse(config: RedirectorConfig): Buffer {
  const encoder = new TdfEncoder();

  // ADDR union - contains the server address
  encoder.writeUnion('ADDR', 0x00, (enc) => {
    // VALU struct - the actual address value
    enc.writeStructStart('VALU');
    enc.writeString('HOST', config.targetHost);
    enc.writeInteger('IP  ', ipToInt(config.targetHost));
    enc.writeInteger('PORT', config.targetPort);
    enc.writeStructEnd();
  });

  // SECU - whether to use SSL (0 = no SSL, 1 = SSL)
  encoder.writeInteger('SECU', 0);

  // XDNS - whether to use XDNS resolution (0 = no)
  encoder.writeInteger('XDNS', 0);

  return encoder.build();
}

/**
 * Convert an IP address string to a 32-bit integer
 */
function ipToInt(ip: string): number {
  // If it's a hostname, return 0 (game will use the HOST string)
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;
  return parts.reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}

/**
 * Handle a single client connection to the redirector
 */
function handleConnection(socket: net.Socket, config: RedirectorConfig): void {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[Redirector] Client connected: ${addr}`);

  let buffer: Buffer = Buffer.alloc(0);

  socket.on('data', (data) => {
    buffer = Buffer.concat([buffer, data]) as Buffer;
    console.log(`[Redirector] Received ${data.length} bytes from ${addr}`);
    console.log(`[Redirector] Hex: ${data.toString('hex').substring(0, 200)}`);

    // Try to read complete packets
    let result = readPacket(buffer);
    while (result) {
      const { packet, remaining } = result;
      buffer = remaining as Buffer;

      console.log(`[Redirector] Packet: component=0x${packet.header.component.toString(16)} command=0x${packet.header.command.toString(16)} msgType=0x${packet.header.msgType.toString(16)} msgId=${packet.header.msgId}`);

      handlePacket(socket, packet, config);
      result = readPacket(buffer);
    }
  });

  socket.on('close', () => {
    console.log(`[Redirector] Client disconnected: ${addr}`);
  });

  socket.on('error', (err) => {
    console.log(`[Redirector] Socket error from ${addr}: ${err.message}`);
  });
}

/**
 * Handle a decoded Blaze packet
 */
function handlePacket(socket: net.Socket, packet: BlazePacket, config: RedirectorConfig): void {
  if (packet.header.component === BlazeComponent.REDIRECTOR) {
    if (packet.header.command === RedirectorCommand.GET_SERVER_INSTANCE) {
      console.log(`[Redirector] GetServerInstance request - redirecting to ${config.targetHost}:${config.targetPort}`);
      const responseBody = buildServerInstanceResponse(config);
      const reply = buildReply(packet, responseBody);
      socket.write(reply);
      console.log(`[Redirector] Sent redirect response (${reply.length} bytes)`);
      // Close connection after redirect (this is normal behavior)
      setTimeout(() => socket.end(), 100);
    } else {
      console.log(`[Redirector] Unknown redirector command: 0x${packet.header.command.toString(16)}`);
    }
  } else {
    console.log(`[Redirector] Unknown component: 0x${packet.header.component.toString(16)}`);
  }
}

/**
 * Start the Blaze redirector server
 */
export function startRedirector(config: RedirectorConfig): net.Server {
  const server = net.createServer((socket) => {
    handleConnection(socket, config);
  });

  server.listen(REDIRECTOR_PORT, '0.0.0.0', () => {
    console.log(`[Redirector] Listening on port ${REDIRECTOR_PORT}`);
    console.log(`[Redirector] Will redirect clients to ${config.targetHost}:${config.targetPort}`);
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EACCES') {
      console.error(`[Redirector] Permission denied on port ${REDIRECTOR_PORT}. Try running as administrator.`);
    } else if (err.code === 'EADDRINUSE') {
      console.error(`[Redirector] Port ${REDIRECTOR_PORT} already in use.`);
    } else {
      console.error(`[Redirector] Server error: ${err.message}`);
    }
  });

  return server;
}
