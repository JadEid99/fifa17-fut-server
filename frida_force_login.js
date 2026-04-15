/*
 * Frida v37: Read the CreateAccountResponse field descriptor table
 * to find the exact TDF tags the decoder expects.
 *
 * The response struct is registered at 0x14487cba0 with:
 *   - Decoder at LAB_146e023e0
 *   - Field descriptor at PTR_DAT_144878060
 *   - Field count = 2
 *
 * The field descriptor table contains the TDF tag (3 bytes), type,
 * and offset for each field in the response struct.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v37: Read TDF Field Descriptors ===');

// Read the CreateAccountResponse field descriptor
try {
    var fieldDescPtr = addr(0x4878060); // PTR_DAT_144878060
    var fieldDesc = fieldDescPtr.readPointer();
    console.log('[CA-RESP] Field descriptor pointer at 0x144878060 = ' + fieldDesc);
    
    // Each field descriptor is typically 0x20-0x30 bytes containing:
    // - 3-byte encoded tag
    // - 1-byte type
    // - offset in struct
    // - other metadata
    // Let's dump the raw bytes
    if (!fieldDesc.isNull()) {
        console.log('[CA-RESP] Field descriptor raw dump (first 0x80 bytes):');
        var bytes = fieldDesc.readByteArray(0x80);
        var arr = new Uint8Array(bytes);
        for (var row = 0; row < 0x80; row += 16) {
            var hex = '';
            var ascii = '';
            for (var col = 0; col < 16 && row + col < 0x80; col++) {
                hex += ('0' + arr[row + col].toString(16)).slice(-2) + ' ';
                ascii += (arr[row + col] >= 32 && arr[row + col] < 127) ? String.fromCharCode(arr[row + col]) : '.';
            }
            console.log('  ' + ('0' + row.toString(16)).slice(-2) + ': ' + hex + ' ' + ascii);
        }
        
        // Try to decode TDF tags from the descriptor
        // TDF tags are 3 bytes encoded as: ((c0-0x20)<<2)|((c1-0x20)>>4), etc.
        // Let's look for patterns
        for (var i = 0; i < 0x60; i++) {
            // Check if bytes at i look like a TDF tag (3 bytes where decoded chars are A-Z0-9 )
            var b0 = arr[i], b1 = arr[i+1], b2 = arr[i+2];
            var c0 = (b0 >> 2) + 0x20;
            var c1 = ((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20;
            var c2 = ((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20;
            var c3 = (b2 & 0x3F) + 0x20;
            if (c0 >= 0x20 && c0 <= 0x7E && c1 >= 0x20 && c1 <= 0x7E && 
                c2 >= 0x20 && c2 <= 0x7E && c3 >= 0x20 && c3 <= 0x7E) {
                var tag = String.fromCharCode(c0) + String.fromCharCode(c1) + String.fromCharCode(c2) + String.fromCharCode(c3);
                // Only show if it looks like a real tag (uppercase letters/digits/space)
                if (tag.match(/^[A-Z0-9 ]{4}$/)) {
                    console.log('[CA-RESP] Possible TDF tag at offset ' + i + ': "' + tag + '"');
                }
            }
        }
    }
} catch(e) {
    console.log('[CA-RESP] Error reading field descriptor: ' + e);
}

// Also read the CheckLegalDocResponse field descriptor (for comparison)
try {
    var legalFieldDescPtr = addr(0x487a100); // PTR_DAT_14487a100
    var legalFieldDesc = legalFieldDescPtr.readPointer();
    console.log('\n[LEGAL-RESP] Field descriptor pointer at 0x14487a100 = ' + legalFieldDesc);
    if (!legalFieldDesc.isNull()) {
        console.log('[LEGAL-RESP] Raw dump (first 0x40 bytes):');
        var bytes2 = legalFieldDesc.readByteArray(0x40);
        var arr2 = new Uint8Array(bytes2);
        for (var row = 0; row < 0x40; row += 16) {
            var hex = '';
            for (var col = 0; col < 16 && row + col < 0x40; col++) {
                hex += ('0' + arr2[row + col].toString(16)).slice(-2) + ' ';
            }
            console.log('  ' + ('0' + row.toString(16)).slice(-2) + ': ' + hex);
        }
    }
} catch(e) {
    console.log('[LEGAL-RESP] Error: ' + e);
}

// Also read the GetLegalDocContentResponse field descriptor
try {
    var tosFieldDescPtr = addr(0x48787e0); // PTR_DAT_1448787e0
    var tosFieldDesc = tosFieldDescPtr.readPointer();
    console.log('\n[TOS-RESP] Field descriptor pointer at 0x1448787e0 = ' + tosFieldDesc);
    if (!tosFieldDesc.isNull()) {
        console.log('[TOS-RESP] Raw dump (first 0x80 bytes):');
        var bytes3 = tosFieldDesc.readByteArray(0x80);
        var arr3 = new Uint8Array(bytes3);
        for (var row = 0; row < 0x80; row += 16) {
            var hex = '';
            for (var col = 0; col < 16 && row + col < 0x80; col++) {
                hex += ('0' + arr3[row + col].toString(16)).slice(-2) + ' ';
            }
            console.log('  ' + ('0' + row.toString(16)).slice(-2) + ': ' + hex);
        }
    }
} catch(e) {
    console.log('[TOS-RESP] Error: ' + e);
}

// Read the PreAuth response field descriptor for comparison (we know this works)
try {
    // PreAuth response registration is near the other auth responses
    // From Ghidra: PreAuth decoder at 0x146e19840, field count varies
    // Let's find it by looking at the PreAuth response struct
    // The PreAuth response vtable is at 0x14389f938 (from Frida v35)
    // Actually, let's just read the response object during the RPC decode
    console.log('\n[INFO] Field descriptors read. Check the hex dumps for TDF tag patterns.');
    console.log('[INFO] TDF tags are 3-byte encoded: b0=(c0-0x20)<<2|(c1-0x20)>>4, etc.');
} catch(e) {}

// Also hook the handlers to confirm they fire
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[PA-HANDLER] Called R8=' + args[2]); }
    });
} catch(e) {}
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) { console.log('[CA-HANDLER] Called R8=' + args[2]); }
    });
} catch(e) {}

console.log('=== Frida v37 Ready ===');
