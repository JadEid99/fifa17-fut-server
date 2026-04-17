// Decode the TAIL of BF4's PreAuth response — after QOSS struct
// We know QOSS ends somewhere around byte ~900. The full response is 1361 bytes.
// The remaining ~400 bytes should contain the login types field.

const fullHex = "873ca30107333032313233008e993304001688e0030189e003198ae0031b041c0607090a82e007230f80e00382e00383e00384e00386e003901f87e0038efba6038efba6050101111e6173736f63696174696f6e4c697374536b6970496e697469616c5365740002310014626c617a65536572766572436c69656e7449640017474f532d426c617a655365727665722d4246342d50430012627974657661756c74486f73746e616d65001e627974657661756c742e67616d6573657276696365732e65612e636f6d000e627974657661756c74506f7274000634323231300010627974657661756c74536563757265000574727565001863617073537472696e6756616c69646174696f6e557269001c636c69656e742d737472696e67732e78626f786c6976652e636f6d0010636f6e6e49646c6554696d656f75740004393073001664656661756c745265717565737454696d656f7574000436307300136964656e74697479446973706c61795572690011636f6e736f6c65322f77656c636f6d6500146964656e7469747952656469726563745572690019687474703a2f2f3132372e302e302e312f73756363657373000f6e75636c657573436f6e6e656374001868747470733a2f2f6163636f756e74732e65612e636f6d000d6e75636c65757350726f7879001768747470733a2f2f676174657761792e65612e636f6d000b70696e67506572696f640004333073001a757365724d616e616765724d617843616368656455736572730002300016766f69704865616473657455706461746552617465000531303030000c78626c546f6b656e55726e00106163636f756e74732e65612e636f6d001a786c7370436f6e6e656374696f6e49646c6554696d656f757400043330300000973ca3010733303231323300a6ecf40111626174746c656669656c642d342d706300b69bb20000ba1cf0010a63656d5f65615f696400c29b24010100c2c8740103706300c6fcf3038b7c3303c33840012a716f732d70726f642d62696f2d6475622d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840011162696f2d70726f642d616d732d6266340000b2ec00000ab34c330501030604616d7300c33840012a716f732d70726f642d62696f2d6475622d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840011162696f2d70726f642d616d732d62663400000467727500c33840012a716f732d70726f642d6d33642d62727a2d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840010100000469616400c33840012a716f732d70726f642d62696f2d6961642d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840011162696f2d70726f642d6961642d6266340000046c617800c33840012a716f732d70726f642d62696f2d736a632d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840011162696f2d70726f642d6c61782d6266340000046e727400c33840012a716f732d70726f642d6d33642d6e72742d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee84001116933642d70726f642d6e72742d62663400000473796400c33840012a716f732d70726f642d62696f2d7379642d636f6d6d6f6e2d636f6d6d6f6e2e676f732e65612e636f6d00c33c00009e9102cee840011162696f2d70726f642d7379642d6266340000cf6a640085a088d408d29b650080ade20400cb3ca3010733303231323300cf69720120426c617a652031332e332e312e382e302028434c232031313438323639290a00";

const buf = Buffer.from(fullHex, 'hex');

function decodeTag(b, off) {
  const c0 = String.fromCharCode((b[off] >> 2) + 0x20);
  const c1 = String.fromCharCode(((b[off] & 0x03) << 4 | (b[off+1] >> 4)) + 0x20);
  const c2 = String.fromCharCode(((b[off+1] & 0x0F) << 2 | (b[off+2] >> 6)) + 0x20);
  const c3 = String.fromCharCode((b[off+2] & 0x3F) + 0x20);
  return c0 + c1 + c2 + c3;
}

function decodeVarInt(b, off) {
  let value = BigInt(b[off] & 0x3F);
  let hasMore = (b[off] & 0x80) !== 0;
  off++;
  let shift = 6n;
  while (hasMore && off < b.length) {
    value |= BigInt(b[off] & 0x7F) << shift;
    hasMore = (b[off] & 0x80) !== 0;
    off++;
    shift += 7n;
  }
  return { value, off };
}

// Start from the end of the QOSS struct — search for the QOSS end marker (0x00)
// and then decode what follows. Let's just scan from byte 900 onward.
// Actually let's scan the WHOLE thing but only print the last ~10 top-level fields.

let offset = 0;
let fieldCount = 0;

function skipField(b, off, type) {
  if (type === 0x00) { const r = decodeVarInt(b, off); return r.off; }
  if (type === 0x01) { const r = decodeVarInt(b, off); return r.off + Number(r.value); }
  if (type === 0x02) { const r = decodeVarInt(b, off); return r.off + Number(r.value); }
  if (type === 0x03) { return skipStruct(b, off); }
  if (type === 0x04) {
    const itemType = b[off++];
    const r = decodeVarInt(b, off); off = r.off;
    for (let i = 0; i < Number(r.value); i++) {
      if (itemType === 0x03) off = skipStruct(b, off);
      else { const r2 = decodeVarInt(b, off); off = r2.off; if (itemType === 0x01 || itemType === 0x02) off += Number(r2.value); }
    }
    return off;
  }
  if (type === 0x05) {
    const kt = b[off++], vt = b[off++];
    const r = decodeVarInt(b, off); off = r.off;
    for (let i = 0; i < Number(r.value); i++) {
      if (kt === 0x01) { const r2 = decodeVarInt(b, off); off = r2.off + Number(r2.value); }
      else { const r2 = decodeVarInt(b, off); off = r2.off; }
      if (vt === 0x01) { const r2 = decodeVarInt(b, off); off = r2.off + Number(r2.value); }
      else if (vt === 0x03) { off = skipStruct(b, off); }
      else { const r2 = decodeVarInt(b, off); off = r2.off; }
    }
    return off;
  }
  if (type === 0x06) { const am = b[off++]; if (am !== 0x7F) return skipField(b, off, am > 0x06 ? 0x00 : am); return off; }
  if (type === 0x07) { const r = decodeVarInt(b, off); off = r.off; for (let i = 0; i < Number(r.value); i++) { const r2 = decodeVarInt(b, off); off = r2.off; } return off; }
  return off;
}

function skipStruct(b, off) {
  while (off < b.length && b[off] !== 0x00) {
    off += 3; // tag
    const type = b[off++];
    off = skipField(b, off, type);
  }
  if (off < b.length) off++; // skip 0x00 terminator
  return off;
}

// Decode all top-level fields
while (offset < buf.length) {
  if (buf[offset] === 0x00) { offset++; continue; }
  if (offset + 4 > buf.length) break;
  
  const tag = decodeTag(buf, offset);
  const type = buf[offset + 3];
  const startOff = offset;
  
  offset += 4;
  
  const typeNames = ['INT','STR','BLOB','STRUCT','LIST','MAP','UNION','INTLIST','PAIR','TRIPLE'];
  const tn = typeNames[type] || `0x${type.toString(16)}`;
  
  // For the last few fields, print details
  if (startOff > 800) {
    if (type === 0x00) {
      const r = decodeVarInt(buf, offset); offset = r.off;
      console.log(`@${startOff}: ${tag} ${tn} = ${r.value}`);
    } else if (type === 0x01) {
      const r = decodeVarInt(buf, offset); offset = r.off;
      const s = buf.subarray(offset, offset + Number(r.value) - 1).toString('utf8');
      offset += Number(r.value);
      console.log(`@${startOff}: ${tag} ${tn} = "${s}"`);
    } else if (type === 0x04) {
      const itemType = buf[offset++];
      const r = decodeVarInt(buf, offset); offset = r.off;
      console.log(`@${startOff}: ${tag} LIST itemType=0x${itemType.toString(16)} count=${r.value}`);
      // Skip items
      for (let i = 0; i < Number(r.value); i++) {
        if (itemType === 0x03) offset = skipStruct(buf, offset);
        else { const r2 = decodeVarInt(buf, offset); offset = r2.off; if (itemType === 0x01 || itemType === 0x02) offset += Number(r2.value); }
      }
    } else {
      console.log(`@${startOff}: ${tag} ${tn}`);
      offset = skipField(buf, offset - 4 + 4, type);
    }
  } else {
    offset = skipField(buf, offset, type);
    console.log(`@${startOff}: ${tag} ${tn} (skip to ${offset})`);
  }
  fieldCount++;
}
console.log(`\nTotal top-level fields: ${fieldCount}`);
