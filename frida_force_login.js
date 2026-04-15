/*
 * Frida v38: Hook TDF tag reader to see what tags the CreateAccount
 * decoder tries to read. The TDF reader at 0x1479ab0f0 is called
 * for each field. We need to see what tag it's looking for.
 *
 * From v34: During CreateAccount decode, TDF-READ is called 3 times.
 * We need to see what tag each call is trying to match.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v38: TDF Tag Reader Trace ===');

var currentContext = '';

// Track RPC decode context
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen > 4) {
                var arr = new Uint8Array(bufStart.readByteArray(4));
                if (arr[0] === 0x86 && arr[1] === 0x7d && arr[2] === 0x70) currentContext = 'CreateAccount';
                else if (arr[0] === 0x86 && arr[1] === 0xeb && arr[2] === 0xee) currentContext = 'PreAuth';
                else if (arr[0] === 0x8e && arr[1] === 0xfb && arr[2] === 0xa6) currentContext = 'FetchClientConfig';
                else currentContext = 'bodyLen=' + bodyLen;
            }
        } catch(e) { currentContext = 'unknown'; }
        console.log('\n[RPC] ENTER [' + currentContext + ']');
    },
    onLeave: function(retval) {
        console.log('[RPC] LEAVE [' + currentContext + ']');
        currentContext = '';
    }
});

// Hook TDF field reader at 0x1479ab0f0
// This function reads a TDF field. We need to see what it reads.
// RCX = field descriptor object
Interceptor.attach(addr(0x79ab0f0), {
    onEnter: function(args) {
        if (!currentContext) return;
        var fieldDesc = args[0];
        // The field descriptor object contains the tag info
        // Try to read the tag from the descriptor
        try {
            // The tag might be at a fixed offset in the descriptor
            // Let's dump the first 0x30 bytes to find it
            var dump = new Uint8Array(fieldDesc.readByteArray(0x30));
            var hex = '';
            for (var i = 0; i < 0x30; i++) {
                hex += ('0' + dump[i].toString(16)).slice(-2) + ' ';
                if ((i + 1) % 16 === 0) hex += '\n    ';
            }
            
            // Try to find a TDF tag in the descriptor
            // The tag hash/id might be at a known offset
            // Let's try reading a 4-byte value at various offsets
            var tag4 = fieldDesc.add(0x00).readU32();
            var tag8 = fieldDesc.add(0x08).readU32();
            var tagC = fieldDesc.add(0x0C).readU32();
            var tag10 = fieldDesc.add(0x10).readU32();
            var tag14 = fieldDesc.add(0x14).readU32();
            var tag18 = fieldDesc.add(0x18).readU32();
            
            console.log('[TDF-READ] [' + currentContext + '] desc=' + fieldDesc + 
                ' vals: +0=' + tag4.toString(16) + ' +8=' + tag8.toString(16) + 
                ' +C=' + tagC.toString(16) + ' +10=' + tag10.toString(16) +
                ' +14=' + tag14.toString(16) + ' +18=' + tag18.toString(16));
            
            // Also try to read a string at +0x08 or +0x10 (tag name)
            try {
                var s8 = fieldDesc.add(0x08).readPointer().readUtf8String(10);
                if (s8 && s8.length >= 2) console.log('[TDF-READ]   +0x08 -> "' + s8 + '"');
            } catch(e) {}
            try {
                var s10 = fieldDesc.add(0x10).readPointer().readUtf8String(10);
                if (s10 && s10.length >= 2) console.log('[TDF-READ]   +0x10 -> "' + s10 + '"');
            } catch(e) {}
            try {
                var s18 = fieldDesc.add(0x18).readPointer().readUtf8String(10);
                if (s18 && s18.length >= 2) console.log('[TDF-READ]   +0x18 -> "' + s18 + '"');
            } catch(e) {}
        } catch(e) {
            console.log('[TDF-READ] [' + currentContext + '] desc=' + fieldDesc + ' (read error)');
        }
    }
});

// Hook handlers
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[PA-HANDLER] Called'); }
    });
} catch(e) {}
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) { console.log('[CA-HANDLER] Called'); }
    });
} catch(e) {}

console.log('=== Frida v38 Ready ===');
console.log('Tracing TDF field reads during RPC decode');
