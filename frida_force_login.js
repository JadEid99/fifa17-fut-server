/*
 * Frida v18: Hook TDF parser to see if CreateAccount response body is parsed
 * Also read the string at 0x14388cda0 (Entry 1 field name)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v18 ===');

// Read the unknown string at 0x14388cda0
try {
    var s = ptr(0x14388cda0).readUtf8String(32);
    console.log('[FIELD1_NAME] 0x14388cda0 = "' + s + '"');
} catch(e) { console.log('[FIELD1_NAME] error: ' + e); }

// Read the known string at 0x14388cf0c
try {
    var s2 = ptr(0x14388cf0c).readUtf8String(32);
    console.log('[FIELD2_NAME] 0x14388cf0c = "' + s2 + '"');
} catch(e) { console.log('[FIELD2_NAME] error: ' + e); }

// Hook FUN_146e151d0 - CreateAccount response handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p1 = args[0];
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[CA_RESP] p1=' + p1 + ' p2=' + p2 + ' p3=0x' + (p3>>>0).toString(16));
        if (p3 === 0 && !p2.isNull()) {
            // Dump 64 bytes of the response structure
            var bytes = p2.readByteArray(64);
            var arr = new Uint8Array(bytes);
            var lines = [];
            for (var i = 0; i < arr.length; i += 16) {
                var hex = '';
                for (var j = i; j < Math.min(i+16, arr.length); j++) {
                    hex += ('0' + arr[j].toString(16)).slice(-2) + ' ';
                }
                lines.push('+' + ('00' + i.toString(16)).slice(-3) + ': ' + hex);
            }
            console.log('[CA_RESP] param2 dump:\n' + lines.join('\n'));
            
            // Check specific offsets
            console.log('[CA_RESP] +0x10 (userId): 0x' + p2.add(0x10).readU32().toString(16));
            console.log('[CA_RESP] +0x18 (pnam ptr): ' + p2.add(0x18).readPointer());
            try {
                var pnamPtr = p2.add(0x18).readPointer();
                if (!pnamPtr.isNull()) {
                    console.log('[CA_RESP] pnam string: "' + pnamPtr.readUtf8String(32) + '"');
                }
            } catch(e) {}
        }
    }
});

console.log('=== Ready ===');
