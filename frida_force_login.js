/*
 * Frida v34: Lightweight tracing — NO Stalker (crashes the game).
 *
 * Key finding from v32:
 * - PreAuth vtable+0x30 decoder calls TDF reader 0x1479ab0f0 nine times
 * - CA vtable+0x30 decoder calls only init functions, zero TDF reads
 * - The response object stays empty after CA decode
 *
 * Strategy: Hook the TDF reader function (0x1479ab0f0) and the key
 * functions from the v32 Stalker output to see what happens during
 * the full RPC decode flow (FUN_146db5d60).
 *
 * Also hook FUN_146db5d60 itself to log entry/exit and see if the
 * TDF reader is called between vtable+0x30 and the handler call.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v34: Lightweight RPC Trace (no Stalker) ===');

var currentContext = '';

// ============================================================
// Hook: FUN_146db5d60 — RPC response decoder (entry/exit only)
// ============================================================
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        var bufStart, bufEnd, bodyLen;
        try {
            bufStart = bodyBufObj.add(0x08).readPointer();
            bufEnd = bodyBufObj.add(0x18).readPointer();
            bodyLen = bufEnd.sub(bufStart).toInt32();
        } catch(e) { bodyLen = -1; }

        var label = 'unknown';
        if (bodyLen > 4) {
            try {
                var arr = new Uint8Array(bufStart.readByteArray(4));
                if (arr[0] === 0x86 && arr[1] === 0x7d && arr[2] === 0x70) label = 'CreateAccount';
                else if (arr[0] === 0x86 && arr[1] === 0xeb && arr[2] === 0xee) label = 'PreAuth';
                else if (arr[0] === 0x8e && arr[1] === 0xfb && arr[2] === 0xa6) label = 'FetchClientConfig';
                else if (arr[0] === 0xcf) label = 'Ping';
            } catch(e) {}
        }
        if (bodyLen === 322) label = 'GetServerInstance(XML)';

        currentContext = label;
        console.log('\n[RPC-5d60] ENTER bodyLen=' + bodyLen + ' [' + label + ']');
    },
    onLeave: function(retval) {
        console.log('[RPC-5d60] LEAVE [' + currentContext + ']');
        currentContext = '';
    }
});

// ============================================================
// Hook: TDF field reader at 0x1479ab0f0
// This is called 9 times during PreAuth decode.
// If it's called during CreateAccount, the TDF is being read.
// ============================================================
Interceptor.attach(addr(0x79ab0f0), {
    onEnter: function(args) {
        console.log('[TDF-READ] 0x1479ab0f0 called during [' + currentContext + '] RCX=' + args[0]);
    }
});

// ============================================================
// Hook: PreAuth decoder (vtable+0x30) at 0x146e19840
// ============================================================
Interceptor.attach(addr(0x6e19840), {
    onEnter: function(args) {
        console.log('[PA-DEC] ENTER [' + currentContext + ']');
    },
    onLeave: function(retval) {
        console.log('[PA-DEC] LEAVE ret=' + retval);
    }
});

// ============================================================
// Hook: CA decoder (vtable+0x30) at 0x146e12a60
// ============================================================
Interceptor.attach(addr(0x6e12a60), {
    onEnter: function(args) {
        console.log('[CA-DEC] ENTER [' + currentContext + '] RCX=' + args[0]);
        // Dump the response object
        try {
            var obj = args[0];
            for (var off = 0; off < 0x30; off += 8) {
                console.log('[CA-DEC]   +0x' + off.toString(16) + ' = ' + obj.add(off).readPointer());
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        console.log('[CA-DEC] LEAVE ret=' + retval);
    }
});

// ============================================================
// Hook: FCC decoder (vtable+0x30) at 0x146e12a00
// ============================================================
Interceptor.attach(addr(0x6e12a00), {
    onEnter: function(args) {
        console.log('[FCC-DEC] ENTER [' + currentContext + ']');
    },
    onLeave: function(retval) {
        console.log('[FCC-DEC] LEAVE ret=' + retval);
    }
});

// ============================================================
// Hook: PreAuth handler at 0x146e1cf10 (patched by DLL)
// ============================================================
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PA-HANDLER] ENTER R8(errCode)=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[PA-HANDLER] LEAVE');
        }
    });
} catch(e) {
    console.log('[PA-HANDLER] Hook failed (DLL patched): ' + e);
}

// ============================================================
// Hook: CA handler at 0x146e151d0 (patched by DLL)
// ============================================================
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[CA-HANDLER] ENTER RCX=' + args[0] + ' R8=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[CA-HANDLER] LEAVE');
        }
    });
} catch(e) {
    console.log('[CA-HANDLER] Hook failed (DLL patched): ' + e);
}

// ============================================================
// Hook: Other key functions from the v32 PreAuth Stalker trace
// These are called during successful PreAuth TDF decode
// ============================================================

// 0x1479ab160 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x79ab160), {
        onEnter: function(args) {
            console.log('[TDF-0x160] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x1479ab1a0 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x79ab1a0), {
        onEnter: function(args) {
            console.log('[TDF-0x1a0] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x1479abd20 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x79abd20), {
        onEnter: function(args) {
            console.log('[TDF-0xd20] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x1479b0190 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x79b0190), {
        onEnter: function(args) {
            console.log('[TDF-0x190] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x146dd57a0 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x6dd57a0), {
        onEnter: function(args) {
            console.log('[RPC-57a0] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x146df37a0 — called during PreAuth decode
try {
    Interceptor.attach(addr(0x6df37a0), {
        onEnter: function(args) {
            console.log('[RPC-37a0] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x146db4be0 — called during both PA and CA decode
try {
    Interceptor.attach(addr(0x6db4be0), {
        onEnter: function(args) {
            console.log('[RPC-4be0] called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x146e06740 — TDF init, called during CA decode
try {
    Interceptor.attach(addr(0x6e06740), {
        onEnter: function(args) {
            console.log('[TDF-INIT] 0x146e06740 called during [' + currentContext + ']');
        }
    });
} catch(e) {}

// 0x146e06180 — called during CA decode
try {
    Interceptor.attach(addr(0x6e06180), {
        onEnter: function(args) {
            console.log('[TDF-6180] 0x146e06180 called during [' + currentContext + ']');
        }
    });
} catch(e) {}

console.log('=== Frida v34 Ready ===');
console.log('Lightweight hooks on TDF reader + key functions');
console.log('No Stalker — should not crash');
