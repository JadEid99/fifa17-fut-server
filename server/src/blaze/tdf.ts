/**
 * TDF (Tag Data Format) Encoder/Decoder
 * 
 * TDF is EA's binary serialization format used inside Blaze packet bodies.
 * Each field has a 3-character tag (encoded as 4 bytes), a type byte, and the value.
 * 
 * Tag encoding: 3 ASCII chars packed into 4 bytes (6 bits per char, base = 0x20)
 * Types: 0x00=Integer, 0x01=String, 0x02=Blob, 0x03=Struct, 0x04=List,
 *        0x05=Map, 0x06=Union, 0x07=IntList, 0x08=ObjectType, 0x09=ObjectId
 */

export enum TdfType {
  INTEGER = 0x00,
  STRING = 0x01,
  BLOB = 0x02,
  STRUCT = 0x03,
  LIST = 0x04,
  MAP = 0x05,
  UNION = 0x06,
  INT_LIST = 0x07,
  OBJECT_TYPE = 0x08,
  OBJECT_ID = 0x09,
}

export class TdfEncoder {
  private buffers: Buffer[] = [];

  /**
   * Encode a 3-char tag into 4 bytes (6 bits per char, offset by 0x20)
   */
  private encodeTag(tag: string): Buffer {
    if (tag.length !== 4) throw new Error(`Tag must be 4 chars, got: "${tag}"`);
    const buf = Buffer.alloc(4);
    // Tags are encoded as 3 chars packed into 3 bytes with the type in the 4th
    // Actually: 4 chars, each mapped to 6 bits, packed into 3 bytes
    const c0 = tag.charCodeAt(0) - 0x20;
    const c1 = tag.charCodeAt(1) - 0x20;
    const c2 = tag.charCodeAt(2) - 0x20;
    const c3 = tag.charCodeAt(3) - 0x20;
    buf[0] = (c0 << 2) | ((c1 >> 4) & 0x03);
    buf[1] = ((c1 & 0x0F) << 4) | ((c2 >> 2) & 0x0F);
    buf[2] = ((c2 & 0x03) << 6) | (c3 & 0x3F);
    return buf;
  }

  private writeTagAndType(tag: string, type: TdfType): void {
    const tagBuf = this.encodeTag(tag);
    this.buffers.push(tagBuf);
    this.buffers.push(Buffer.from([type]));
  }

  /**
   * Encode a variable-length integer (Blaze uses a compressed integer format)
   */
  private encodeVarInt(value: number | bigint): Buffer {
    let v = typeof value === 'bigint' ? value : BigInt(value);
    const bytes: number[] = [];

    if (v < 0n) {
      // Negative values: set sign bit
      v = -v;
      const first = Number(v & 0x3Fn);
      bytes.push(first | 0x80); // sign bit
      v >>= 6n;
    } else {
      const first = Number(v & 0x3Fn);
      bytes.push(first);
      v >>= 6n;
    }

    while (v > 0n) {
      bytes[bytes.length - 1] |= 0x40; // continuation bit
      bytes.push(Number(v & 0x7Fn));
      v >>= 7n;
    }

    return Buffer.from(bytes);
  }

  /**
   * Add an integer field
   */
  writeInteger(tag: string, value: number | bigint): this {
    this.writeTagAndType(tag, TdfType.INTEGER);
    this.buffers.push(this.encodeVarInt(value));
    return this;
  }

  /**
   * Add a string field (null-terminated, length-prefixed with varint)
   */
  writeString(tag: string, value: string): this {
    this.writeTagAndType(tag, TdfType.STRING);
    const strBuf = Buffer.from(value + '\0', 'utf-8');
    this.buffers.push(this.encodeVarInt(strBuf.length));
    this.buffers.push(strBuf);
    return this;
  }

  /**
   * Add a blob field
   */
  writeBlob(tag: string, data: Buffer): this {
    this.writeTagAndType(tag, TdfType.BLOB);
    this.buffers.push(this.encodeVarInt(data.length));
    this.buffers.push(data);
    return this;
  }

  /**
   * Start a struct field. Call endStruct() when done adding fields.
   */
  writeStructStart(tag: string): this {
    this.writeTagAndType(tag, TdfType.STRUCT);
    return this;
  }

  /**
   * End a struct (writes the terminator byte 0x00)
   */
  writeStructEnd(): this {
    this.buffers.push(Buffer.from([0x00]));
    return this;
  }

  /**
   * Add a union field
   */
  writeUnion(tag: string, type: number, callback: (encoder: TdfEncoder) => void): this {
    this.writeTagAndType(tag, TdfType.UNION);
    this.buffers.push(Buffer.from([type]));
    if (type !== 0x7F) {
      // 0x7F means empty/unset union
      callback(this);
    }
    return this;
  }

  /**
   * Write a list of integers
   */
  writeIntList(tag: string, values: number[]): this {
    this.writeTagAndType(tag, TdfType.INT_LIST);
    this.buffers.push(this.encodeVarInt(values.length));
    for (const v of values) {
      this.buffers.push(this.encodeVarInt(v));
    }
    return this;
  }

  /**
   * Write a list field
   */
  writeList(tag: string, itemType: TdfType, count: number, callback: (encoder: TdfEncoder, index: number) => void): this {
    this.writeTagAndType(tag, TdfType.LIST);
    this.buffers.push(Buffer.from([itemType]));
    this.buffers.push(this.encodeVarInt(count));
    for (let i = 0; i < count; i++) {
      callback(this, i);
      if (itemType === TdfType.STRUCT) {
        this.buffers.push(Buffer.from([0x00])); // struct terminator
      }
    }
    return this;
  }

  /**
   * Build the final buffer
   */
  build(): Buffer {
    return Buffer.concat(this.buffers);
  }
}
