/**
 * Blaze Protocol Codec
 * 
 * Handles encoding/decoding of Blaze packets.
 * Blaze uses a 12-byte header followed by TDF-encoded body data.
 */

import { BlazePacket, BlazePacketHeader, MessageType } from './types.js';

const HEADER_SIZE = 12;

/**
 * Decode a Blaze packet header from a buffer
 */
export function decodeHeader(buf: Buffer): BlazePacketHeader | null {
  if (buf.length < HEADER_SIZE) return null;

  const length = buf.readUInt16BE(0);
  const component = buf.readUInt16BE(2);
  const command = buf.readUInt16BE(4);
  const error = buf.readUInt16BE(6);
  const msgTypeAndId = buf.readUInt32BE(8);
  const msgType = (msgTypeAndId >> 16) & 0xF000;
  const msgId = msgTypeAndId & 0xFFFF;

  return {
    length,
    component,
    command,
    error,
    msgType: msgType as MessageType,
    msgId,
  };
}

/**
 * Encode a Blaze packet header into a buffer
 */
export function encodeHeader(header: BlazePacketHeader): Buffer {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt16BE(header.length, 0);
  buf.writeUInt16BE(header.component, 2);
  buf.writeUInt16BE(header.command, 4);
  buf.writeUInt16BE(header.error, 6);
  const msgTypeAndId = ((header.msgType & 0xF000) << 16) | (header.msgId & 0xFFFF);
  buf.writeUInt32BE(msgTypeAndId, 8);
  return buf;
}

/**
 * Try to read a complete Blaze packet from a buffer.
 * Returns the packet and remaining bytes, or null if incomplete.
 */
export function readPacket(buf: Buffer): { packet: BlazePacket; remaining: Buffer } | null {
  if (buf.length < HEADER_SIZE) return null;

  const header = decodeHeader(buf);
  if (!header) return null;

  const totalSize = HEADER_SIZE + header.length;
  if (buf.length < totalSize) return null;

  const body = buf.subarray(HEADER_SIZE, totalSize);
  const remaining = buf.subarray(totalSize);

  return {
    packet: { header, body },
    remaining,
  };
}

/**
 * Build a complete Blaze packet buffer from header info and body
 */
export function buildPacket(
  component: number,
  command: number,
  msgType: MessageType,
  msgId: number,
  body: Buffer,
  error: number = 0
): Buffer {
  const header = encodeHeader({
    length: body.length,
    component,
    command,
    error,
    msgType,
    msgId,
  });
  return Buffer.concat([header, body]);
}

/**
 * Build a reply packet for a given request
 */
export function buildReply(request: BlazePacket, body: Buffer, error: number = 0): Buffer {
  return buildPacket(
    request.header.component,
    request.header.command,
    error ? MessageType.ERROR_REPLY : MessageType.REPLY,
    request.header.msgId,
    body,
    error
  );
}
