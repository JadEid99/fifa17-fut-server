// Frida v3: Brute-force dump of the member info table
// The table is at 0x144867628 (confirmed by runtime read).
// 14 entries. We don't know the entry size or layout.
// Strategy: dump a large block of raw bytes starting at the table
// and visually inspect for patterns.

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v3] base: ' + base);

function decodeTdfTag(b0, b1, b2) {
    var c0 = String.fromCharCode((b0 >> 2) + 0x20);
    var c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
    var c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
    var c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
    return c0 + c1 + c2 + c3;
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

// Hook PreAuth handler to confirm timing
try {
    Interceptor.attach(base.add(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PreAuth] err=' + args[2].toInt32());
        }
    });
} catch(e) {}

setTimeout(function() {
    console.log('\n[v3] === MEMBER INFO TABLE RAW DUMP ===');

    var tableBase = base.add(0x4867628);
    console.log('[v3] Table at: ' + tableBase);
    console.log('[v3] Expected 14 entries\n');

    // Dump 1024 bytes starting at the table — enough for 14 entries of up to 72 bytes each
    try {
        var raw = new Uint8Array(tableBase.readByteArray(1024));
        
        // Print full hex dump
        for (var i = 0; i < raw.length; i += 16) {
            var hex = '';
            var ascii = '';
            for (var j = 0; j < 16 && i+j < raw.length; j++) {
                hex += ('0' + raw[i+j].toString(16)).slice(-2) + ' ';
                ascii += (raw[i+j] >= 0x20 && raw[i+j] < 0x7f) ? String.fromCharCode(raw[i+j]) : '.';
            }
            console.log('  ' + i.toString(16).padStart(4,'0') + ': ' + hex.padEnd(49) + ascii);
        }
        
        // Now try to decode TDF tags at every 4-byte aligned offset
        console.log('\n[v3] === TAG SCAN (every offset) ===');
        for (var off = 0; off < raw.length - 3; off++) {
            var tag = decodeTdfTag(raw[off], raw[off+1], raw[off+2]);
            if (/^[A-Z]{3,4}$/.test(tag.trim())) {
                console.log('  @' + off.toString(16).padStart(3,'0') + ': ' + tag.trim() + 
                    ' [' + raw[off].toString(16) + ' ' + raw[off+1].toString(16) + ' ' + raw[off+2].toString(16) + ']');
            }
        }
        
        // Try to find string pointers in the table
        console.log('\n[v3] === STRING POINTER SCAN ===');
        for (var off = 0; off < 1024; off += 8) {
            var s = tryStr(tableBase.add(off));
            if (s) {
                console.log('  @' + off.toString(16).padStart(3,'0') + ': "' + s + '"');
            }
        }
        
    } catch(e) {
        console.log('[v3] Dump error: ' + e);
    }

    // Also dump the ALTERNATE interpretation: the table pointer at 0x4874a90
    // points to 0x144867628. But maybe 0x4874a90 itself contains useful data.
    console.log('\n[v3] === DATA AT 0x4874a90 (table pointer region) ===');
    try {
        var ptrRegion = base.add(0x4874a90);
        var raw2 = new Uint8Array(ptrRegion.readByteArray(256));
        for (var i = 0; i < raw2.length; i += 16) {
            var hex = '';
            for (var j = 0; j < 16 && i+j < raw2.length; j++) {
                hex += ('0' + raw2[i+j].toString(16)).slice(-2) + ' ';
            }
            console.log('  ' + i.toString(16).padStart(4,'0') + ': ' + hex);
        }
        // String scan
        for (var off = 0; off < 256; off += 8) {
            var s = tryStr(ptrRegion.add(off));
            if (s) console.log('  str@' + off.toString(16) + ': "' + s + '"');
        }
    } catch(e) {
        console.log('[v3] Region error: ' + e);
    }

    // Dump the registration function's data area
    // FUN_146df6160 stores data at DAT_144875600 through DAT_144875638
    console.log('\n[v3] === REGISTRATION DATA (0x4875600-0x4875660) ===');
    try {
        var regData = base.add(0x4875600);
        var raw3 = new Uint8Array(regData.readByteArray(96));
        for (var i = 0; i < raw3.length; i += 16) {
            var hex = '';
            for (var j = 0; j < 16 && i+j < raw3.length; j++) {
                hex += ('0' + raw3[i+j].toString(16)).slice(-2) + ' ';
            }
            console.log('  ' + i.toString(16).padStart(4,'0') + ': ' + hex);
        }
        for (var off = 0; off < 96; off += 8) {
            var s = tryStr(regData.add(off));
            if (s) console.log('  str@' + off.toString(16) + ': "' + s + '"');
        }
    } catch(e) {
        console.log('[v3] Reg error: ' + e);
    }

    console.log('\n[v3] === DONE ===');
}, 15000);
