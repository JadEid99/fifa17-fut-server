// Frida v4: Dump loginSM+0xC8 to understand why login types are empty
//
// KEY FINDING: The login types at loginSM+0x218/+0x220 are NOT populated
// by TDF decoding. They're populated by FUN_146e1c1f0 which reads from
// loginSM+0xC8. If loginSM+0xC8 is zero, no login types are created.
//
// This script dumps loginSM+0xC8 and surrounding fields to understand
// what data is expected there and where it comes from.

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v4] base: ' + base);

function hexDump(addr, len) {
    try {
        var bytes = addr.readByteArray(len);
        var arr = new Uint8Array(bytes);
        var lines = [];
        for (var i = 0; i < arr.length; i += 16) {
            var hex = '';
            for (var j = 0; j < 16 && i+j < arr.length; j++) {
                hex += ('0' + arr[i+j].toString(16)).slice(-2) + ' ';
            }
            lines.push('  ' + i.toString(16).padStart(4,'0') + ': ' + hex);
        }
        return lines.join('\n');
    } catch(e) { return '  unreadable: ' + e; }
}

function tryStr(addr) {
    try {
        var p = addr.readPointer();
        if (p.isNull() || p.compare(ptr(0x1000)) < 0) return null;
        var s = p.readCString();
        if (s && s.length > 1 && s.length < 200 && /^[a-zA-Z_]/.test(s)) return s;
    } catch(e) {}
    return null;
}

// Hook FUN_146e1c3f0 (LoginTypesProcessor) to dump loginSM state
try {
    Interceptor.attach(base.add(0x6e1c3f0), {
        onEnter: function(args) {
            var loginSM = args[0];
            var respField = args[1];
            console.log('\n[LoginTypesProc] loginSM=' + loginSM + ' respField=' + respField);

            // Dump loginSM+0xB0 through +0x100 (the area around +0xC8)
            console.log('\n[loginSM] +0x80 to +0x100:');
            console.log(hexDump(loginSM.add(0x80), 128));

            // The critical value: loginSM+0xC8
            try {
                var val_c8 = loginSM.add(0xC8).readPointer();
                console.log('\n[loginSM] +0xC8 = ' + val_c8 + (val_c8.isNull() ? ' *** ZERO — THIS IS WHY LOGIN TYPES ARE EMPTY ***' : ''));

                if (!val_c8.isNull()) {
                    console.log('[loginSM] +0xC8 points to:');
                    console.log(hexDump(val_c8, 64));
                }
            } catch(e) {
                console.log('[loginSM] +0xC8 read error: ' + e);
            }

            // Also dump +0xE0 (used when +0xC8 check passes)
            try {
                var val_e0 = loginSM.add(0xE0).readPointer();
                console.log('[loginSM] +0xE0 = ' + val_e0);
                if (!val_e0.isNull()) {
                    console.log('[loginSM] +0xE0 points to:');
                    console.log(hexDump(val_e0, 64));
                }
            } catch(e) {}

            // Dump +0xB8 (the list object that FUN_146e1c1f0 operates on)
            try {
                var val_b8 = loginSM.add(0xB8).readPointer();
                console.log('[loginSM] +0xB8 vtable = ' + val_b8);
            } catch(e) {}

            // Dump +0x08 (parent pointer, used to read +0x53f)
            try {
                var parent = loginSM.add(0x08).readPointer();
                console.log('[loginSM] +0x08 parent = ' + parent);
                if (!parent.isNull()) {
                    var flag53f = parent.add(0x53f).readU8();
                    console.log('[loginSM] parent+0x53f = ' + flag53f);
                    // Also read parent+0x53c (used by FUN_146e1c1f0)
                    var val53c = parent.add(0x53c).readU16();
                    console.log('[loginSM] parent+0x53c = ' + val53c);
                }
            } catch(e) {}

            // Dump +0x1A0 (checked at end of FUN_146e1c1f0)
            try {
                var val_1a0 = loginSM.add(0x1A0).readU16();
                console.log('[loginSM] +0x1A0 = ' + val_1a0);
            } catch(e) {}

            // Dump the full loginSM from +0x00 to +0x2A0 to see everything
            console.log('\n[loginSM] FULL DUMP +0x00 to +0x2A0:');
            console.log(hexDump(loginSM, 0x2A0));
        },
        onLeave: function() {
            console.log('[LoginTypesProc] RETURNED');
        }
    });
    console.log('[v4] Hooked LoginTypesProcessor');
} catch(e) {
    console.log('[v4] Hook error: ' + e);
}

// Also hook FUN_146e1c1f0 directly to see what it does
try {
    Interceptor.attach(base.add(0x6e1c1f0), {
        onEnter: function(args) {
            var loginSM = args[0];
            console.log('\n[FUN_146e1c1f0] ENTERED loginSM=' + loginSM);
            try {
                var val_c8 = loginSM.add(0xC8).readPointer();
                console.log('  +0xC8 = ' + val_c8);
                var val_b8_vtable = loginSM.add(0xB8).readPointer();
                console.log('  +0xB8 vtable = ' + val_b8_vtable);
            } catch(e) {}
        },
        onLeave: function() {
            console.log('[FUN_146e1c1f0] RETURNED');
        }
    });
    console.log('[v4] Hooked FUN_146e1c1f0');
} catch(e) {
    console.log('[v4] Hook FUN_146e1c1f0 error: ' + e);
}

// Hook PreAuth handler for timing reference
try {
    Interceptor.attach(base.add(0x6e1cf10), {
        onEnter: function(args) {
            console.log('\n[PreAuth] err=' + args[2].toInt32());
        }
    });
    console.log('[v4] Hooked PreAuth handler');
} catch(e) {}

console.log('[v4] All hooks set. Waiting for PreAuth...');
