// Frida script v2: Find the unknown PreAuthResponse TDF tag
//
// APPROACH: Hook the TDF wire decoder to log every tag it reads
// during PreAuth response processing. The decoder reads 3-byte tags
// from the wire and looks them up in the member info table.
// By logging every tag the decoder encounters, we get the complete
// list of tags the game EXPECTS (even if our server doesn't send them all).
//
// From Ghidra: The TDF decoder reads tags via a function that extracts
// 3 bytes from the stream and decodes them into a 4-char tag string.
// We hook this function and log every tag.

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try {
        var mod = Process.enumerateModules()[0];
        base = mod.base;
    } catch(e2) {
        base = ptr(0x140000000);
    }
}
console.log('[v2] FIFA17.exe base: ' + base);

function decodeTdfTag(b0, b1, b2) {
    var c0 = String.fromCharCode((b0 >> 2) + 0x20);
    var c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
    var c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
    var c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
    return (c0 + c1 + c2 + c3).trim();
}

function hexDump(addr, len) {
    try {
        var bytes = addr.readByteArray(len);
        var arr = new Uint8Array(bytes);
        var lines = [];
        for (var i = 0; i < arr.length; i += 16) {
            var hex = '';
            for (var j = 0; j < 16 && i + j < arr.length; j++) {
                hex += ('0' + arr[i+j].toString(16)).slice(-2) + ' ';
            }
            lines.push('    ' + i.toString(16).padStart(4,'0') + ': ' + hex);
        }
        return lines.join('\n');
    } catch(e) { return '    unreadable: ' + e; }
}

// ============================================================
// APPROACH A: Hook PreAuth handler + LoginTypesProcessor
// to confirm the field at +0x120 and dump its contents
// ============================================================
var preAuthActive = false;

try {
    Interceptor.attach(base.add(0x6e1cf10), {
        onEnter: function(args) {
            var err = args[2].toInt32();
            console.log('\n[PreAuth] HANDLER ENTERED err=' + err);
            if (err === 0) {
                preAuthActive = true;
                var resp = args[1];
                // Dump field at +0x120 (login types)
                console.log('[PreAuth] resp+0x120 (login types field):');
                console.log(hexDump(resp.add(0x120), 64));
                // Check if the list at +0x120 has any entries
                // The list's internal array is at field+0x60 and field+0x68
                try {
                    var listStart = resp.add(0x120 + 0x60).readPointer();
                    var listEnd = resp.add(0x120 + 0x68).readPointer();
                    console.log('[PreAuth] login types list: start=' + listStart + ' end=' + listEnd);
                    if (!listStart.isNull() && !listEnd.isNull()) {
                        var count = listEnd.sub(listStart).toInt32() / 0x20;
                        console.log('[PreAuth] login types count: ' + count);
                    } else {
                        console.log('[PreAuth] login types list is EMPTY (null pointers)');
                    }
                } catch(e) {
                    console.log('[PreAuth] error reading list: ' + e);
                }
            }
        },
        onLeave: function() {
            preAuthActive = false;
            console.log('[PreAuth] HANDLER RETURNED');
        }
    });
    console.log('[v2] Hooked PreAuth handler at ' + base.add(0x6e1cf10));
} catch(e) {
    console.log('[v2] Failed to hook PreAuth handler: ' + e);
}

// ============================================================
// APPROACH B: Scan the PreAuth response TDF wire bytes for tags
// The server sends TDF-encoded data. The game receives it and
// decodes it. We can read the raw TDF bytes from the response
// body BEFORE decoding and extract all tags ourselves.
//
// Hook the RPC response dispatcher to capture the raw PreAuth
// response bytes as they arrive from the server.
// ============================================================

// FUN_146db5d60 is called to decode RPC responses
// It receives the raw TDF body bytes
try {
    Interceptor.attach(base.add(0x6db5d60), {
        onEnter: function(args) {
            // param_2 = error code, param_3 = data pointer, param_4 = data object
            // We need to find the raw bytes. Let me log all params.
            if (preAuthActive) {
                console.log('\n[RpcDecode] Called during PreAuth!');
                console.log('  param1=' + args[0] + ' param2=' + args[1]);
                console.log('  param3=' + args[2] + ' param4=' + args[3]);
            }
        }
    });
    console.log('[v2] Hooked RPC decoder at ' + base.add(0x6db5d60));
} catch(e) {
    console.log('[v2] Failed to hook RPC decoder: ' + e);
}

// ============================================================
// APPROACH C: Scan the .rdata section for the member info table
// using a MUCH wider scan and looking for the specific pattern
// of TDF field descriptors that reference known PreAuthResponse
// string addresses.
//
// From the Ghidra dump, we know these string addresses:
// s_PreAuthResponse = 0x1438952f8
// s_Blaze::Util::PreAuthResponse = 0x1438952d8
// The member info entries should reference field name strings
// that are near these addresses in the string table.
// ============================================================

setTimeout(function() {
    console.log('\n[v2] Running memory scans...');

    // Scan for the PreAuthResponse string to verify our base address
    try {
        var strAddr = base.add(0x48952f8);
        var str = strAddr.readCString();
        console.log('[v2] String at 0x48952f8: "' + str + '"');
    } catch(e) {
        console.log('[v2] Cannot read string at 0x48952f8: ' + e);
    }

    // Read the member info table pointer
    try {
        var tablePtr = base.add(0x4874a90);
        var tableBase = tablePtr.readPointer();
        console.log('[v2] Member info table ptr at 0x4874a90 -> ' + tableBase);
        var count = base.add(0x4875638).readU32();
        console.log('[v2] Field count: ' + count);

        // The table at 0x144867628 is NOT an array of pointers to individual entries.
        // From the previous dump, entries [0] through [13] had mostly invalid pointers.
        // The table might be a flat array of INLINE structs.
        //
        // From Taggi source, each entry is 6 bytes: [tag:3][sep:1][type:1][next:1]
        // But that's the ON-DISK format. In memory, the BlazeSDK uses a different
        // representation with vtables and pointers.
        //
        // Let me try reading the table as 6-byte Taggi entries directly from the
        // BINARY IMAGE (not the runtime data). The binary image is mapped at base.
        // The Taggi entries would be in the .rdata section.
        //
        // From the NHL Taggi output, the PreAuthResponse entries start at offset
        // 0x01B451EC in the NHL binary. For FIFA 17, the offset would be different
        // but the PATTERN is the same: a sequence of 6-byte entries with valid tags.
        //
        // Let me scan a HUGE range of the .rdata section for sequences of valid
        // Taggi entries that include known PreAuthResponse tags.

        console.log('\n[v2] === WIDE BINARY SCAN FOR TAGGI ENTRIES ===');
        
        // Scan the entire .rdata section (typically 0x143500000 to 0x144900000)
        // That's too large. Let me scan around known string addresses.
        // PreAuthResponse strings are at 0x1438952xx.
        // Member info data is at 0x144867xxx to 0x144875xxx.
        // Let me scan 0x14386xxxx to 0x14390xxxx (about 640KB)
        
        var scanRanges = [
            // Around the PreAuth-related strings
            { start: base.add(0x3880000), len: 0x20000, name: '.rdata 0x3880000' },
            { start: base.add(0x38A0000), len: 0x20000, name: '.rdata 0x38A0000' },
            // Around the member info table
            { start: base.add(0x4860000), len: 0x20000, name: '.rdata 0x4860000' },
        ];
        
        var knownTags = ['ASRC','CIDS','CONF','EEFA','ESRC','INST','MINR','NASP',
                         'PILD','PLAT','QOSS','RSRC','SVER','ANON','CNGN','PTAG'];
        var knownSet = {};
        for (var k = 0; k < knownTags.length; k++) knownSet[knownTags[k]] = true;
        
        for (var ri = 0; ri < scanRanges.length; ri++) {
            var range = scanRanges[ri];
            console.log('\n  Scanning ' + range.name + ' (' + range.len + ' bytes)...');
            try {
                var scanBytes = new Uint8Array(range.start.readByteArray(range.len));
                
                // Look for chains of valid Taggi entries
                for (var off = 0; off < scanBytes.length - 6; off++) {
                    var tag = decodeTdfTag(scanBytes[off], scanBytes[off+1], scanBytes[off+2]);
                    var sep = scanBytes[off+3];
                    var typeB = scanBytes[off+4];
                    var nextB = scanBytes[off+5];
                    
                    // Check if this looks like a valid Taggi entry
                    if (!/^[A-Z][A-Z0-9 ]{0,3}$/.test(tag)) continue;
                    if (sep !== 0x00 && sep !== 0x01) continue;
                    if (typeB > 0x20) continue;
                    
                    // Check if it's a known PreAuthResponse tag
                    if (!knownSet[tag]) continue;
                    
                    // Found a known tag! Now follow the chain
                    var chain = [];
                    var chainOff = off;
                    while (chainOff < scanBytes.length - 6) {
                        var ct = decodeTdfTag(scanBytes[chainOff], scanBytes[chainOff+1], scanBytes[chainOff+2]);
                        var cs = scanBytes[chainOff+3];
                        var cty = scanBytes[chainOff+4];
                        var cn = scanBytes[chainOff+5];
                        
                        if (!/^[A-Z][A-Z0-9 ]{0,3}$/.test(ct)) break;
                        if (cs !== 0x00 && cs !== 0x01) break;
                        if (cty > 0x20) break;
                        
                        chain.push({ off: chainOff, tag: ct, type: cty, next: cn });
                        
                        if (cn === 0) break; // end of chain
                        if (cn < 6 || cn > 64) break; // invalid next
                        chainOff += cn;
                    }
                    
                    // Only report chains with 8+ entries that contain multiple known tags
                    var knownCount = 0;
                    for (var ci = 0; ci < chain.length; ci++) {
                        if (knownSet[chain[ci].tag]) knownCount++;
                    }
                    
                    if (chain.length >= 8 && knownCount >= 5) {
                        var addr = range.start.add(off);
                        console.log('\n  >>> CANDIDATE SCHEMA at ' + addr + ' (' + chain.length + ' fields, ' + knownCount + ' known):');
                        for (var ci = 0; ci < chain.length; ci++) {
                            var e = chain[ci];
                            var marker = knownSet[e.tag] ? '' : ' <<<< UNKNOWN';
                            console.log('    ' + range.start.add(e.off) + ': ' + e.tag + 
                                ' type=0x' + e.type.toString(16).padStart(2,'0') + 
                                ' next=' + e.next + marker);
                        }
                    }
                    
                    // Skip past this chain to avoid duplicate reports
                    if (chain.length >= 8) {
                        off = chain[chain.length-1].off;
                    }
                }
            } catch(e) {
                console.log('  Scan error: ' + e);
            }
        }
    } catch(e) {
        console.log('[v2] Table read error: ' + e);
    }

    console.log('\n[v2] === SCAN COMPLETE ===');
}, 15000);
