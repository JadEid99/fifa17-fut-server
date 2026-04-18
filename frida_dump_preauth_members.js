// Frida script: Dump FIFA 17 PreAuthResponse TDF member info table
// Goal: Find the unknown TDF tag at field offset +0x120 (login types)
//
// Known from Ghidra:
//   - PreAuthResponse registration: FUN_146df6160
//   - Member info table pointer: PTR_DAT_144874a90
//   - Field count: DAT_144875638 = 0x0E (14)
//   - PreAuth handler reads param_2+0x120 as login types list
//   - NHL has 13 fields, FIFA 17 has 14 — the extra one is the target
//
// Strategy:
//   1. Read the member info table at multiple interpretations
//   2. Hook the PreAuth response handler to dump the live response object
//   3. Hook the TDF decoder to log every tag it processes during PreAuth decode
//   4. Scan memory around known addresses for TDF tag byte patterns

'use strict';

var base = null;
try {
    base = Module.findBaseAddress('FIFA17.exe');
} catch(e) {
    console.log('[DUMP] Module.findBaseAddress failed: ' + e);
}
if (!base) {
    try {
        var mod = Process.enumerateModules()[0];
        base = mod.base;
        console.log('[DUMP] Using first module: ' + mod.name + ' at ' + base);
    } catch(e2) {
        base = ptr(0x140000000);
        console.log('[DUMP] Fallback to hardcoded base: ' + base);
    }
}
console.log('[DUMP] FIFA17.exe base: ' + base);

// ============================================================
// KNOWN ADDRESSES (Ghidra base 0x140000000)
// ============================================================
var ADDR = {
    memberInfoTablePtr: base.add(0x4874a90),   // PTR_DAT_144874a90 — pointer to member info array
    memberInfoTableAlt: base.add(0x4867628),   // Alternate address found in live dump (April 17)
    fieldCount:         base.add(0x4875638),   // DAT_144875638 — count = 14
    preAuthRegFn:       base.add(0x6df6160),   // FUN_146df6160 — PreAuthResponse registration
    preAuthHandler:     base.add(0x6e1cf10),   // FUN_146e1cf10 — PreAuth response handler
    loginTypesProc:     base.add(0x6e1c3f0),   // FUN_146e1c3f0 — LoginTypesProcessor
    tdfRegisterType:    base.add(0x79ab1e0),   // FUN_1479ab1e0 — TDF type registration
    preAuthDecoder:     base.add(0x6df24e0),   // LAB_146df24e0 — PreAuth TDF decoder label
    preAuthResponseStr: base.add(0x48952d8),   // s_Blaze::Util::PreAuthResponse
    preAuthResponseStr2:base.add(0x48952f8),   // s_PreAuthResponse
};

function decodeTdfTag(b0, b1, b2) {
    const c0 = String.fromCharCode((b0 >> 2) + 0x20);
    const c1 = String.fromCharCode(((b0 & 0x03) << 4 | (b1 >> 4)) + 0x20);
    const c2 = String.fromCharCode(((b1 & 0x0F) << 2 | (b2 >> 6)) + 0x20);
    const c3 = String.fromCharCode((b2 & 0x3F) + 0x20);
    return (c0 + c1 + c2 + c3).trim();
}

function isValidTag(tag) {
    return /^[A-Z][A-Z0-9 ]{0,3}$/.test(tag);
}

function hexDump(addr, len) {
    try {
        const bytes = addr.readByteArray(len);
        const arr = new Uint8Array(bytes);
        let lines = [];
        for (let i = 0; i < arr.length; i += 16) {
            let hex = '';
            let ascii = '';
            for (let j = 0; j < 16 && i + j < arr.length; j++) {
                hex += ('0' + arr[i+j].toString(16)).slice(-2) + ' ';
                ascii += (arr[i+j] >= 0x20 && arr[i+j] < 0x7f) ? String.fromCharCode(arr[i+j]) : '.';
            }
            lines.push(('    ' + (i).toString(16).padStart(4,'0') + ': ' + hex.padEnd(49) + ascii));
        }
        return lines.join('\n');
    } catch(e) {
        return '    (unreadable: ' + e + ')';
    }
}

function tryReadString(addr) {
    try {
        const p = addr.readPointer();
        // Check if pointer is in a reasonable range (game image or heap)
        if (p.isNull()) return null;
        const s = p.readCString();
        if (s && s.length > 1 && s.length < 200 && /^[a-zA-Z_:]/.test(s)) return s;
    } catch(e) {}
    return null;
}

// ============================================================
// APPROACH 1: Direct table read with multiple interpretations
// ============================================================
function dumpMemberInfoTable() {
    console.log('\n' + '='.repeat(70));
    console.log('[APPROACH 1] Direct member info table read');
    console.log('='.repeat(70));

    try {
        const count = ADDR.fieldCount.readU32();
        console.log('Field count at ' + ADDR.fieldCount + ': ' + count);

        // The table pointer itself
        const rawTablePtr = ADDR.memberInfoTablePtr;
        console.log('Table pointer location: ' + rawTablePtr);

        // Interpretation A: PTR_DAT is a pointer TO a pointer array
        console.log('\n--- Interpretation A: Array of pointers ---');
        try {
            const tableBase = rawTablePtr.readPointer();
            console.log('Table base (deref): ' + tableBase);
            for (let i = 0; i < Math.min(count, 20); i++) {
                const entryPtr = tableBase.add(i * 8).readPointer();
                console.log('\n[' + i + '] ptr=' + entryPtr);
                console.log(hexDump(entryPtr, 80));
                // Try tag decode at various offsets
                for (let off of [0, 4, 8, 12, 16, 20, 24]) {
                    try {
                        const b = new Uint8Array(entryPtr.add(off).readByteArray(3));
                        const tag = decodeTdfTag(b[0], b[1], b[2]);
                        if (isValidTag(tag)) console.log('    tag@' + off + ': ' + tag);
                    } catch(e) {}
                }
                // Try string pointers at various offsets
                for (let off of [0, 8, 16, 24, 32, 40, 48, 56, 64]) {
                    const s = tryReadString(entryPtr.add(off));
                    if (s) console.log('    str@' + off + ': "' + s + '"');
                }
            }
        } catch(e) {
            console.log('  Error: ' + e);
        }

        // Interpretation B: Flat struct array ---
        // Try BOTH addresses: Ghidra's PTR_DAT_144874a90 and live dump's 0x144867628
        console.log('\n--- Interpretation B: Flat struct array at both addresses ---');
        for (const tableAddr of [rawTablePtr, ADDR.memberInfoTableAlt]) {
        try {
            console.log('\n  Table address: ' + tableAddr);
            // Each entry might be 24, 32, 40, or 48 bytes
            for (let stride of [24, 32, 40, 48]) {
                console.log('\n  Stride=' + stride + ':');
                let validCount = 0;
                for (let i = 0; i < count; i++) {
                    const entryAddr = rawTablePtr.add(i * stride);
                    for (let off of [0, 4, 8, 12, 16]) {
                        try {
                            const b = new Uint8Array(entryAddr.add(off).readByteArray(3));
                            const tag = decodeTdfTag(b[0], b[1], b[2]);
                            if (isValidTag(tag)) {
                                console.log('    [' + i + '] @' + off + ': ' + tag);
                                validCount++;
                            }
                        } catch(e) {}
                    }
                }
                if (validCount >= 5) console.log('  >>> ' + validCount + ' valid tags found with stride ' + stride);
            }
        } catch(e) {
            console.log('  Error: ' + e);
        }
        } // end for tableAddr

        // Interpretation C: Scan a wide region around the table pointer for tag patterns
        console.log('\n--- Interpretation C: Wide scan around table address ---');
        try {
            // Scan around BOTH known addresses (Ghidra + live dump from April 17)
            for (const scanAddr of [rawTablePtr, ADDR.memberInfoTableAlt]) {
                console.log('  Scanning around ' + scanAddr + ':');
                const scanStart = scanAddr.sub(256);
                const scanLen = 2048;
            const scanBytes = new Uint8Array(scanStart.readByteArray(scanLen));
            let found = [];
            for (let off = 0; off < scanBytes.length - 5; off++) {
                const tag = decodeTdfTag(scanBytes[off], scanBytes[off+1], scanBytes[off+2]);
                // Check separator byte (should be 0x00 or 0x01)
                if (isValidTag(tag) && (scanBytes[off+3] === 0x00 || scanBytes[off+3] === 0x01)) {
                    const typeB = scanBytes[off+4];
                    const nextB = scanBytes[off+5];
                    // Reasonable type byte (0x00-0x20) and next byte (0 or 4-64)
                    if (typeB <= 0x20 && (nextB === 0 || (nextB >= 4 && nextB <= 64))) {
                        found.push({ off: off - 256, tag, type: typeB, next: nextB });
                    }
                }
            }
            if (found.length > 0) {
                console.log('  Found ' + found.length + ' Taggi-format entries:');
                for (const f of found) {
                    console.log('    @' + (f.off >= 0 ? '+' : '') + f.off + ': ' + f.tag + 
                        ' type=0x' + f.type.toString(16) + ' next=' + f.next);
                }
            } else {
                console.log('  No Taggi-format entries found in scan range');
            }
            } // end for scanAddr
        } catch(e) {
            console.log('  Scan error: ' + e);
        }

    } catch(e) {
        console.log('[APPROACH 1] Fatal error: ' + e);
    }
}

// ============================================================
// APPROACH 2: Hook PreAuth handler, dump response object at +0x120
// ============================================================
function hookPreAuthHandler() {
    console.log('\n' + '='.repeat(70));
    console.log('[APPROACH 2] Hook PreAuth handler — dump response+0x120');
    console.log('='.repeat(70));

    try {
        Interceptor.attach(ADDR.preAuthHandler, {
            onEnter: function(args) {
                this.param1 = args[0];
                this.param2 = args[1];
                this.param3 = args[2];
                const err = args[2].toInt32();
                console.log('\n[PreAuthHandler] ENTERED');
                console.log('  param1 (this)=' + args[0] + ' param2 (resp)=' + args[1] + ' param3 (err)=' + err);

                if (err === 0) {
                    const resp = args[1];
                    // Dump the response object around offset 0x120
                    console.log('  resp+0x100..0x180:');
                    console.log(hexDump(resp.add(0x100), 128));

                    // The field at +0x120 is a TDF list/struct object
                    // Read its vtable and internal pointers
                    try {
                        const fieldAddr = resp.add(0x120);
                        const vtable = fieldAddr.readPointer();
                        console.log('  resp+0x120 vtable: ' + vtable);
                        console.log('  resp+0x120 dump (96 bytes):');
                        console.log(hexDump(fieldAddr, 96));

                        // The list's start/end pointers might be at internal offsets
                        // From analysis: the list object at +0x1b8 in loginSM has
                        // array pointers at +0x60 and +0x68 relative to the list start
                        // So resp+0x120+0x60 and resp+0x120+0x68 might have the array
                        for (let off of [0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68]) {
                            try {
                                const val = fieldAddr.add(off).readPointer();
                                if (!val.isNull()) {
                                    console.log('  resp+0x120+0x' + off.toString(16) + ': ' + val);
                                }
                            } catch(e) {}
                        }

                        // Try to read the tag from the vtable area
                        // The vtable might have a getName() or getTag() method
                        if (!vtable.isNull()) {
                            console.log('  vtable dump:');
                            console.log(hexDump(vtable, 64));
                        }
                    } catch(e) {
                        console.log('  Error reading resp+0x120: ' + e);
                    }

                    // Also dump the FULL response object to find all field boundaries
                    console.log('\n  Full response object (first 0x250 bytes):');
                    console.log(hexDump(resp, 0x250));
                }
            },
            onLeave: function(retval) {
                console.log('[PreAuthHandler] RETURNED');
            }
        });
        console.log('  PreAuth handler hooked at ' + ADDR.preAuthHandler);
    } catch(e) {
        console.log('  Hook error: ' + e);
    }
}

// ============================================================
// APPROACH 3: Hook LoginTypesProcessor to see what it reads
// ============================================================
function hookLoginTypesProcessor() {
    console.log('\n' + '='.repeat(70));
    console.log('[APPROACH 3] Hook LoginTypesProcessor — trace +0x120 access');
    console.log('='.repeat(70));

    try {
        Interceptor.attach(ADDR.loginTypesProc, {
            onEnter: function(args) {
                const loginSM = args[0];
                const respField = args[1];  // This is resp+0x120
                console.log('\n[LoginTypesProc] ENTERED');
                console.log('  loginSM=' + loginSM + ' respField(resp+0x120)=' + respField);

                // Dump the field object passed as param_2
                console.log('  respField dump (128 bytes):');
                console.log(hexDump(respField, 128));

                // Read the vtable
                try {
                    const vtable = respField.readPointer();
                    console.log('  respField vtable: ' + vtable);

                    // Try calling vtable+0x10 (getName or getTypeInfo)
                    // This is risky but might give us the type name
                    try {
                        const getInfoFn = vtable.add(0x10).readPointer();
                        console.log('  vtable+0x10 (getInfo?): ' + getInfoFn);
                    } catch(e) {}
                } catch(e) {}

                this.loginSM = loginSM;
            },
            onLeave: function(retval) {
                // After processing, check the login types array
                try {
                    const start = this.loginSM.add(0x218).readPointer();
                    const end = this.loginSM.add(0x220).readPointer();
                    const count = start.isNull() ? 0 : end.sub(start).toInt32() / 0x20;
                    console.log('[LoginTypesProc] RETURNED — array count=' + count +
                        ' start=' + start + ' end=' + end);
                } catch(e) {
                    console.log('[LoginTypesProc] RETURNED — error reading array: ' + e);
                }
            }
        });
        console.log('  LoginTypesProcessor hooked at ' + ADDR.loginTypesProc);
    } catch(e) {
        console.log('  Hook error: ' + e);
    }
}

// ============================================================
// APPROACH 4: Hook TDF type registration to catch PreAuthResponse members
// ============================================================
function hookTdfRegistration() {
    console.log('\n' + '='.repeat(70));
    console.log('[APPROACH 4] Hook FUN_1479ab1e0 — TDF type registration');
    console.log('='.repeat(70));

    let preAuthSeen = false;

    try {
        Interceptor.attach(ADDR.tdfRegisterType, {
            onEnter: function(args) {
                // FUN_1479ab1e0(dest, typeCode, hash, nameStr, ...)
                // args[0] = destination address
                // args[1] = type code
                // args[2] = hash
                // args[3] = name string pointer
                try {
                    const dest = args[0];
                    const typeCode = args[1].toInt32();
                    const hash = '0x' + args[2].toString(16);
                    let name = '';
                    try { name = args[3].readCString(); } catch(e) {}

                    // Only log PreAuthResponse-related registrations
                    if (name.indexOf('PreAuthResponse') >= 0 || name.indexOf('PreAuth') >= 0) {
                        console.log('[TdfReg] ' + name + ' type=' + typeCode + ' hash=' + hash + ' dest=' + dest);
                        preAuthSeen = true;
                    }

                    // After PreAuthResponse is registered, log the next ~20 registrations
                    // (these are likely the member fields)
                    if (preAuthSeen) {
                        console.log('[TdfReg] dest=' + dest + ' type=' + typeCode + ' hash=' + hash + ' name="' + name + '"');
                    }
                } catch(e) {}
            }
        });
        console.log('  TDF registration hooked at ' + ADDR.tdfRegisterType);
    } catch(e) {
        console.log('  Hook error: ' + e);
    }
}

// ============================================================
// APPROACH 5: Scan the binary for Taggi-format entries near PreAuth strings
// ============================================================
function scanBinaryForTags() {
    console.log('\n' + '='.repeat(70));
    console.log('[APPROACH 5] Binary scan for Taggi-format TDF entries');
    console.log('='.repeat(70));

    // Known PreAuthResponse tags from NHL (for validation)
    const knownTags = new Set(['ASRC','CIDS','CONF','EEFA','ESRC','INST','MINR','NASP','PILD','PLAT','QOSS','RSRC','SVER',
                               'ANON','CNGN','PTAG']);  // Also Blaze3SDK standard

    try {
        // Scan the .rdata section around the PreAuthResponse string addresses
        // The member info table should be near these strings
        const scanRegions = [
            { start: ADDR.preAuthResponseStr.sub(0x2000), len: 0x4000, name: 'around PreAuthResponse string' },
            { start: ADDR.memberInfoTablePtr.sub(0x1000), len: 0x3000, name: 'around member info table ptr' },
            { start: ADDR.memberInfoTableAlt.sub(0x1000), len: 0x3000, name: 'around alt table addr 0x4867628' },
            { start: base.add(0x4874000), len: 0x2000, name: 'rdata 0x4874000-0x4876000' },
        ];

        for (const region of scanRegions) {
            console.log('\n  Scanning ' + region.name + ' (' + region.start + ', ' + region.len + ' bytes)');
            try {
                const bytes = new Uint8Array(region.start.readByteArray(region.len));
                let groups = [];
                let currentGroup = [];

                for (let off = 0; off < bytes.length - 5; off++) {
                    const tag = decodeTdfTag(bytes[off], bytes[off+1], bytes[off+2]);
                    const sep = bytes[off+3];
                    const typeB = bytes[off+4];
                    const nextB = bytes[off+5];

                    if (isValidTag(tag) && (sep === 0x00 || sep === 0x01) && typeB <= 0x20) {
                        const entry = { off, tag, sep, type: typeB, next: nextB, 
                                       addr: region.start.add(off) };

                        if (nextB === 0) {
                            // End of group
                            currentGroup.push(entry);
                            if (currentGroup.length >= 8) {
                                groups.push([...currentGroup]);
                            }
                            currentGroup = [];
                        } else if (nextB >= 4 && nextB <= 64) {
                            currentGroup.push(entry);
                            // Verify chain: next entry should be at off+nextB
                            if (off + nextB < bytes.length - 5) {
                                const nextTag = decodeTdfTag(bytes[off+nextB], bytes[off+nextB+1], bytes[off+nextB+2]);
                                if (!isValidTag(nextTag)) {
                                    currentGroup = [];
                                }
                            }
                        } else {
                            currentGroup = [];
                        }
                    }
                }

                // Print groups that look like PreAuthResponse (have known tags)
                for (const group of groups) {
                    const tags = group.map(e => e.tag);
                    const knownCount = tags.filter(t => knownTags.has(t)).length;
                    if (knownCount >= 5) {
                        console.log('\n  >>> CANDIDATE PreAuthResponse schema (' + group.length + ' fields, ' + knownCount + ' known):');
                        for (const e of group) {
                            const marker = knownTags.has(e.tag) ? '' : ' <<<< UNKNOWN';
                            console.log('    ' + e.addr + ': ' + e.tag + 
                                ' type=0x' + e.type.toString(16).padStart(2,'0') + 
                                ' next=' + e.next + marker);
                        }
                    }
                }
            } catch(e) {
                console.log('  Scan error: ' + e);
            }
        }
    } catch(e) {
        console.log('[APPROACH 5] Error: ' + e);
    }
}

// ============================================================
// RUN ALL APPROACHES
// ============================================================
console.log('\n[DUMP] Starting PreAuthResponse member info dump...');
console.log('[DUMP] Timestamp: ' + new Date().toISOString());

// Approaches 2-4 are hooks — set them up immediately
hookPreAuthHandler();
hookLoginTypesProcessor();
hookTdfRegistration();

// Approaches 1 and 5 read memory — run after a delay to ensure game is initialized
setTimeout(function() {
    console.log('\n[DUMP] Running memory reads (T+15s)...');
    dumpMemberInfoTable();
    scanBinaryForTags();
    console.log('\n[DUMP] === ALL APPROACHES COMPLETE ===');
    console.log('[DUMP] Look for "CANDIDATE PreAuthResponse schema" or "UNKNOWN" tags above.');
    console.log('[DUMP] The unknown tag between NASP and PILD is the login types field.');
}, 15000);
