/*
 * Hook the TDF decoder to capture ALL tags it reads from the PreAuth response.
 * Also hook the PreAuth response object constructor to find which field
 * maps to offset +0x120.
 *
 * Strategy: Hook FUN_146e1cf10 (PreAuth handler) and when it fires,
 * dump the ENTIRE decoded response object to find the TDF list at +0x120.
 * Then hook the TDF Visit/decode function to see what tags are processed.
 *
 * Usage: frida -p <PID> -l frida_decode_preauth_tags.js
 */

"use strict";
const base = Process.getModuleByName("FIFA17.exe").base;
function addr(off) { return base.add(off); }

function decodeTag3(b0, b1, b2) {
  const c0 = String.fromCharCode((b0 >> 2) + 0x20);
  const c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
  const c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
  const c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
  return c0 + c1 + c2 + c3;
}

console.log("=== PreAuth TDF Tag Decoder ===");

// Hook PreAuth handler to get the response object pointer
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) {
    this.resp = args[1];
    const err = args[2].toInt32();
    console.log("[PreAuth] handler called, resp=" + this.resp + " err=" + err);
    
    if (err === 0 && !this.resp.isNull()) {
      // Dump the response object around offset +0x120
      // The TDF list at +0x120 has: vtable(8) + flags(8) + type/count(8) + data_ptr(8)
      console.log("[PreAuth] Response object dump (+0x100 to +0x180):");
      for (let off = 0x100; off <= 0x180; off += 8) {
        try {
          const val = this.resp.add(off).readU64();
          console.log("  +" + off.toString(16) + ": 0x" + val.toString(16));
        } catch(e) {}
      }
      
      // Now scan the ENTIRE response object for all TDF list objects
      // (identified by vtable = 0x143889d10 or similar list vtables)
      console.log("[PreAuth] Scanning response for TDF list objects...");
      for (let off = 0; off < 0x280; off += 8) {
        try {
          const vtable = this.resp.add(off).readPointer();
          // Check if this looks like a TDF list vtable (in the 0x14388xxxx range)
          if (vtable.compare(ptr("0x143889000")) >= 0 && vtable.compare(ptr("0x14389a000")) < 0) {
            console.log("  +" + off.toString(16) + ": vtable=" + vtable + " (possible TDF list/struct)");
          }
        } catch(e) {}
      }
    }
  },
  onLeave: function(ret) {
    console.log("[PreAuth] handler returned");
  }
});

// Hook the TDF read/visit function that processes individual fields.
// In BlazeSDK, the TDF decoder calls a "visit" method for each field.
// The visit method receives the tag and writes to the appropriate offset.
//
// From Ghidra, the PreAuth response decoder is at LAB_146df24e0.
// It's called via vtable. Let's hook the generic TDF read function instead.
//
// FUN_1479ab1e0 is the TDF type registration function (called during init).
// The actual decoder uses FUN_146db5d60 (RPC response decoder) which
// dispatches to vtable+0x30 on the response object.
//
// Let's hook the TDF stream reader that reads individual tags from the wire.
// In BlazeSDK, this is typically TdfDecoder::readTag() or similar.
//
// Actually, the simplest approach: hook the RPC response decoder
// FUN_146db5d60 and log what it does.

// Hook RPC builder to catch when PreAuth response is being built
Interceptor.attach(addr(0x6dab760), {
  onEnter: function(args, ctx) {
    const comp = ctx.r8.toInt32() & 0xFFFF;
    const cmd = ctx.r9.toInt32() & 0xFFFF;
    if (comp === 9 && cmd === 7) {
      console.log("[RPC] Building PreAuth request (comp=9 cmd=7)");
    }
  }
});

// The most direct approach: read the member info table entries properly.
// From the schema dump, the table at 0x144874a90 contains 14 pointers.
// But some pointers are NULL and some point to data.
// Let me try reading the table as an array of TdfMemberInfo structs
// where each struct starts with a pointer to a TdfFieldInfo.
//
// Actually, from the Ghidra registration code:
//   PTR_PTR_144875630 = (undefined *)&PTR_DAT_144874a90;
// This means 0x144875630 contains a POINTER TO the table.
// And 0x144874a90 IS the table (array of entries).
//
// Let me read the table differently — as raw memory at 0x144874a90,
// looking for 3-byte tag patterns.

console.log("\n=== Reading member info table raw bytes ===");
try {
  const tableBase = ptr("0x144874a90");
  // Read 14 * 64 bytes = 896 bytes (generous, covers any entry size)
  const raw = tableBase.readByteArray(896);
  const bytes = new Uint8Array(raw);
  
  // Scan for valid 3-byte TDF tags. A valid tag has all 4 decoded chars
  // in the range 0x20-0x5F (space to underscore).
  console.log("Scanning for valid TDF tags in table memory:");
  for (let i = 0; i < bytes.length - 3; i++) {
    const b0 = bytes[i], b1 = bytes[i+1], b2 = bytes[i+2];
    const c0 = (b0 >> 2) + 0x20;
    const c1 = ((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20;
    const c2 = ((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20;
    const c3 = (b2 & 0x3F) + 0x20;
    
    // Check if all 4 chars are printable uppercase + space
    if (c0 >= 0x20 && c0 <= 0x5F && c1 >= 0x20 && c1 <= 0x5F &&
        c2 >= 0x20 && c2 <= 0x5F && c3 >= 0x20 && c3 <= 0x5F) {
      const tag = String.fromCharCode(c0, c1, c2, c3);
      // Filter: at least 2 uppercase letters (real tags are like ASRC, CIDS, etc.)
      const upper = tag.replace(/[^A-Z]/g, '').length;
      if (upper >= 3) {
        console.log("  offset " + i.toString(16) + ": " + 
                    b0.toString(16).padStart(2,'0') + 
                    b1.toString(16).padStart(2,'0') + 
                    b2.toString(16).padStart(2,'0') + 
                    " -> " + tag);
      }
    }
  }
} catch(e) {
  console.log("Table scan error: " + e.message);
}

// Also scan the area around the PreAuth response TDF type registration
// The registration at 0x144875600 has nearby data that might contain tags
console.log("\n=== Scanning PreAuth registration area ===");
try {
  const regBase = ptr("0x144874a00");
  const raw = regBase.readByteArray(512);
  const bytes = new Uint8Array(raw);
  
  for (let i = 0; i < bytes.length - 3; i++) {
    const b0 = bytes[i], b1 = bytes[i+1], b2 = bytes[i+2];
    const c0 = (b0 >> 2) + 0x20;
    const c1 = ((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20;
    const c2 = ((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20;
    const c3 = (b2 & 0x3F) + 0x20;
    
    if (c0 >= 0x20 && c0 <= 0x5F && c1 >= 0x20 && c1 <= 0x5F &&
        c2 >= 0x20 && c2 <= 0x5F && c3 >= 0x20 && c3 <= 0x5F) {
      const tag = String.fromCharCode(c0, c1, c2, c3);
      const upper = tag.replace(/[^A-Z]/g, '').length;
      if (upper >= 3) {
        const addr = regBase.add(i);
        console.log("  0x" + addr.toString(16) + " (+" + i.toString(16) + "): " + 
                    b0.toString(16).padStart(2,'0') + 
                    b1.toString(16).padStart(2,'0') + 
                    b2.toString(16).padStart(2,'0') + 
                    " -> " + tag);
      }
    }
  }
} catch(e) {
  console.log("Reg scan error: " + e.message);
}

// Finally, scan the TDF decoder function itself for embedded tag constants
// The decoder at LAB_146df24e0 likely has CMP instructions with tag values
console.log("\n=== Scanning PreAuth TDF decoder for tag constants ===");
try {
  const decoderBase = addr(0x6df24e0);
  const raw = decoderBase.readByteArray(2048);
  const bytes = new Uint8Array(raw);
  
  // Look for 3-byte sequences that decode to valid tags
  // In x86-64, CMP instructions often have immediate values
  // Tags might appear as: 81 F? XX YY ZZ 00 (CMP reg, imm32)
  for (let i = 0; i < bytes.length - 6; i++) {
    // Look for CMP r32, imm32 patterns (81 F8-FF XX XX XX 00)
    if (bytes[i] === 0x81 && (bytes[i+1] & 0xF8) >= 0xF8) {
      const imm = bytes[i+2] | (bytes[i+3] << 8) | (bytes[i+4] << 16);
      if (imm > 0 && (bytes[i+5] === 0x00 || bytes[i+5] === 0x01)) {
        // Try decoding as tag
        const b0 = (imm >> 16) & 0xFF, b1 = (imm >> 8) & 0xFF, b2 = imm & 0xFF;
        const c0 = (b0 >> 2) + 0x20;
        const c1 = ((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20;
        const c2 = ((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20;
        const c3 = (b2 & 0x3F) + 0x20;
        if (c0 >= 0x41 && c0 <= 0x5A && c1 >= 0x20 && c1 <= 0x5F) {
          const tag = String.fromCharCode(c0, c1, c2, c3);
          console.log("  decoder+" + i.toString(16) + ": CMP imm=0x" + 
                      imm.toString(16) + " -> " + tag);
        }
      }
    }
    // Also look for MOV r32, imm32 (B8-BF XX XX XX 00)
    if ((bytes[i] & 0xF8) === 0xB8) {
      const imm = bytes[i+1] | (bytes[i+2] << 8) | (bytes[i+3] << 16);
      if (imm > 0x800000 && (bytes[i+4] === 0x00 || bytes[i+4] === 0x01)) {
        const b0 = (imm >> 16) & 0xFF, b1 = (imm >> 8) & 0xFF, b2 = imm & 0xFF;
        const c0 = (b0 >> 2) + 0x20;
        const c1 = ((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20;
        const c2 = ((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20;
        const c3 = (b2 & 0x3F) + 0x20;
        if (c0 >= 0x41 && c0 <= 0x5A && c1 >= 0x20 && c1 <= 0x5F) {
          const tag = String.fromCharCode(c0, c1, c2, c3);
          console.log("  decoder+" + i.toString(16) + ": MOV imm=0x" + 
                      imm.toString(16) + " -> " + tag);
        }
      }
    }
  }
} catch(e) {
  console.log("Decoder scan error: " + e.message);
}

console.log("\n=== Done ===");
