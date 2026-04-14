/*
 * Frida v17: Read CreateAccountResponse field definitions from memory
 * and trace what TDF tags the game expects
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v17 - Read CreateAccountResponse fields ===');

// Read the field definition table for CreateAccountResponse
// PTR_DAT_144878060 points to the field array
// Each field entry in BlazeSDK is typically: {tag(u32), type(u8), ...}
try {
    var fieldTablePtr = ptr(0x144878060);
    console.log('[FIELDS] CreateAccountResponse field table at: ' + fieldTablePtr);
    
    // Read raw bytes around the field table
    var rawBytes = fieldTablePtr.readByteArray(128);
    console.log('[FIELDS] Raw bytes (128):');
    var arr = new Uint8Array(rawBytes);
    var hex = '';
    for (var i = 0; i < arr.length; i++) {
        hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
        if ((i + 1) % 16 === 0) {
            console.log('[FIELDS]   ' + ('000' + (i-15).toString(16)).slice(-4) + ': ' + hex);
            hex = '';
        }
    }
    if (hex) console.log('[FIELDS]   ' + hex);
    
    // TDF tags are 3 bytes encoded. Try to decode potential tags
    // Also read the pointers that might be in the table
    for (var i = 0; i < 64; i += 8) {
        var val = fieldTablePtr.add(i).readU64();
        if (val > 0x140000000 && val < 0x150000000) {
            // This looks like a code/data pointer
            console.log('[FIELDS] +' + i.toString(16) + ': ptr 0x' + val.toString(16));
            // Try to read string at that address
            try {
                var str = ptr(val.toString()).readUtf8String(32);
                if (str && str.length > 0 && str.length < 30) {
                    console.log('[FIELDS]   -> "' + str + '"');
                }
            } catch(e) {}
        } else if (val !== 0) {
            console.log('[FIELDS] +' + i.toString(16) + ': 0x' + val.toString(16));
        }
    }
} catch(e) {
    console.log('[FIELDS] Error reading field table: ' + e);
}

// Also read the CreateAccountParameters field table for comparison
try {
    var paramTablePtr = ptr(0x14487cb78);
    var paramFieldsPtr = paramTablePtr.readPointer();
    console.log('[PARAMS] CreateAccountParameters name: ' + paramFieldsPtr.readUtf8String());
} catch(e) {}

// Hook FUN_146e151d0 to see the full param_2 structure
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[RESP] param3=0x' + (p3>>>0).toString(16));
        if (p3 === 0 && !p2.isNull()) {
            // Dump the first 32 bytes of the response structure
            try {
                var bytes = p2.readByteArray(48);
                var arr = new Uint8Array(bytes);
                var hex = '';
                for (var i = 0; i < arr.length; i++) {
                    hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                    if ((i + 1) % 16 === 0) {
                        console.log('[RESP] +' + ('00' + (i-15).toString(16)).slice(-3) + ': ' + hex);
                        hex = '';
                    }
                }
            } catch(e) { console.log('[RESP] dump error: ' + e); }
        }
    }
});

console.log('=== Ready ===');
