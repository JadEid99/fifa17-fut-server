/*
 * Dump the PreAuthResponse TDF member info table at runtime.
 * This tells us exactly what TDF tags map to what offsets.
 *
 * Usage: frida -p <FIFA17_PID> -l frida_dump_preauth_schema.js
 *
 * The member info table is at PTR_DAT_144874a90 (pointer to array).
 * Each entry is a TdfMemberInfo struct. We need to figure out the layout.
 *
 * From the Ghidra registration code:
 *   PTR_PTR_144875630 = &PTR_DAT_144874a90;  // member info table pointer
 *   _DAT_144875638 = 0xe;                     // count = 14
 *
 * The table pointer is at 0x144874a90 (absolute address).
 * It points to an array of TdfMemberInfo entries.
 *
 * BlazeSDK TdfMemberInfo typical layout (from openBlase/BlazeSDK sources):
 *   struct TdfMemberInfo {
 *     uint32_t tag;        // 3-byte encoded tag (stored as u32)
 *     uint32_t type;       // TDF type (0=int, 1=str, 3=struct, 4=list, etc.)
 *     uint32_t offset;     // byte offset in the response object
 *     // ... more fields (flags, default value, etc.)
 *   };
 *
 * But the exact layout varies by SDK version. We'll dump raw bytes and
 * try multiple interpretations.
 */

"use strict";

function decodeTag(encoded) {
  // encoded is a 3-byte value packed into u32 (top byte = 0)
  const b0 = (encoded >> 16) & 0xFF;
  const b1 = (encoded >> 8) & 0xFF;
  const b2 = encoded & 0xFF;
  const c0 = String.fromCharCode((b0 >> 2) + 0x20);
  const c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
  const c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
  const c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
  return c0 + c1 + c2 + c3;
}

// The table pointer is stored at 0x144874a90
const tableAddr = ptr("0x144874a90");
console.log("=== PreAuthResponse TDF Member Info Table ===");
console.log("Table pointer address: " + tableAddr);

try {
  const tablePtr = tableAddr.readPointer();
  console.log("Table data at: " + tablePtr);
  
  if (tablePtr.isNull()) {
    console.log("Table pointer is NULL — game may not have initialized yet.");
    console.log("Try running this after the game has loaded past the splash screen.");
  } else {
    // Dump 14 entries. Try different entry sizes (24, 32, 40, 48 bytes).
    for (const entrySize of [24, 32, 40, 48]) {
      console.log("\n--- Trying entry size = " + entrySize + " bytes ---");
      for (let i = 0; i < 14; i++) {
        const entry = tablePtr.add(i * entrySize);
        const raw = entry.readByteArray(entrySize);
        const bytes = new Uint8Array(raw);
        
        // Try interpreting first 4 bytes as tag (big-endian 3 bytes)
        const tag3be = (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
        const tag3le = (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
        
        // Try interpreting bytes 0-3 as u32 LE
        const u32_0 = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
        const u32_4 = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
        const u32_8 = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
        const u32_12 = bytes[12] | (bytes[13] << 8) | (bytes[14] << 16) | (bytes[15] << 24);
        
        // Decode tag from different positions
        let tagBE = "????", tagLE = "????";
        try { tagBE = decodeTag(tag3be); } catch(e) {}
        try { tagLE = decodeTag(tag3le); } catch(e) {}
        
        // Also try u32[0] as tag (some SDKs store it as u32 with padding)
        let tagU32 = "????";
        try { tagU32 = decodeTag(u32_0 & 0xFFFFFF); } catch(e) {}
        let tagU32hi = "????";
        try { tagU32hi = decodeTag((u32_0 >> 8) & 0xFFFFFF); } catch(e) {}
        
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        console.log("[" + i.toString().padStart(2) + "] " + hex);
        console.log("     u32: " + u32_0.toString(16) + " " + u32_4.toString(16) + " " + u32_8.toString(16) + " " + u32_12.toString(16));
        console.log("     tag(BE)=" + tagBE + " tag(LE)=" + tagLE + " tag(u32lo)=" + tagU32 + " tag(u32hi)=" + tagU32hi);
      }
    }
  }
} catch (e) {
  console.log("Error: " + e.message);
}

// Also try reading the table from the LIVE PreAuthResponse object
// The Frida trace showed resp=0x3edd5ef0 but that's session-specific.
// Instead, let's read the static member info table pointer from the
// registration structure.
console.log("\n=== Alternative: Read from registration struct ===");
try {
  // PTR_PTR_144875630 points to the member info table
  const regPtr = ptr("0x144875630");
  const memberInfoPtr = regPtr.readPointer();
  console.log("Registration struct -> member info at: " + memberInfoPtr);
  
  // Count at 0x144875638
  const count = ptr("0x144875638").readU32();
  console.log("Count: " + count);
  
  if (!memberInfoPtr.isNull() && count > 0 && count <= 20) {
    // Each TdfMemberInfo in BlazeSDK 15.x is typically:
    //   +0x00: pointer to tag string (or encoded tag)
    //   +0x08: u32 type
    //   +0x0C: u32 offset in parent struct
    //   +0x10: pointer to default value / sub-type info
    //   +0x18: flags
    // Total: ~32 bytes per entry (but could be 24 or 40)
    
    // Let's just dump the raw pointer array — the table might be an
    // array of POINTERS to TdfMemberInfo structs, not inline structs.
    console.log("\nTrying as array of pointers:");
    for (let i = 0; i < count; i++) {
      const entryPtr = memberInfoPtr.add(i * 8).readPointer();
      console.log("[" + i + "] ptr=" + entryPtr);
      if (!entryPtr.isNull() && entryPtr.compare(ptr("0x140000000")) > 0) {
        try {
          const raw = entryPtr.readByteArray(48);
          const bytes = new Uint8Array(raw);
          const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
          console.log("    " + hex);
          
          // Try reading first 8 bytes as pointer to string
          const strPtr = entryPtr.readPointer();
          if (!strPtr.isNull()) {
            try {
              const s = strPtr.readCString(64);
              console.log("    str: \"" + s + "\"");
            } catch(e) {}
          }
        } catch(e) { console.log("    read err"); }
      }
    }
  }
} catch (e) {
  console.log("Alt error: " + e.message);
}

console.log("\n=== Done ===");
