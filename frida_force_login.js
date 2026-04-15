/*
 * Frida v33: Trace the RPC response decoder (FUN_146db5d60) in detail.
 *
 * Key finding from v32: The CA decoder (vtable+0x30) is just a constructor.
 * It doesn't read TDF data. The PreAuth decoder calls TDF reader functions
 * (0x1479ab0f0 x9) but the CA decoder doesn't call any of them.
 *
 * The TDF reading must happen INSIDE FUN_146db5d60, AFTER vtable+0x30 returns.
 * We need to trace what FUN_146db5d60 does after creating the response object.
 *
 * Strategy: Use Stalker on FUN_146db5d60 for the CreateAccount response
 * to see ALL function calls, including the TDF decode step.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v33: RPC Decoder Deep Trace ===');

// Track message IDs to identify CreateAccount
var msgIdToCmd = {};

// ============================================================
// Hook: FUN_146db5d60 — RPC response decoder
// Trace the ENTIRE function for CreateAccount responses
// ============================================================
var rpcTraced = false;
var rpcTraceForCA = false;

Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var rpc = args[0];
        var errCode = args[1].toInt32();
        var bodyBufObj = args[3];

        var bufStart, bufEnd, bodyLen;
        try {
            bufStart = bodyBufObj.add(0x08).readPointer();
            bufEnd = bodyBufObj.add(0x18).readPointer();
            bodyLen = bufEnd.sub(bufStart).toInt32();
        } catch(e) { bodyLen = -1; }

        console.log('\n[RPC] errCode=' + errCode + ' bodyLen=' + bodyLen);

        // Check if this is the CreateAccount response (169 bytes from our server)
        // or identify by the body content (starts with 86 7d 70 = AGUP)
        var isCA = false;
        if (bodyLen > 4) {
            try {
                var firstBytes = bufStart.readByteArray(4);
                var arr = new Uint8Array(firstBytes);
                // AGUP tag = 86 7d 70, type 00
                if (arr[0] === 0x86 && arr[1] === 0x7d && arr[2] === 0x70) {
                    isCA = true;
                    console.log('[RPC] *** CreateAccount response detected (AGUP first tag) ***');
                }
                // PreAuth starts with 86 eb ee = ANON
                if (arr[0] === 0x86 && arr[1] === 0xeb && arr[2] === 0xee) {
                    console.log('[RPC] PreAuth response detected (ANON first tag)');
                }
            } catch(e) {}
        }

        if (isCA && !rpcTraced) {
            rpcTraced = true;
            rpcTraceForCA = true;
            console.log('[STALKER] Starting FULL trace of FUN_146db5d60 for CreateAccount...');
            this._tid = Process.getCurrentThreadId();
            
            Stalker.follow(this._tid, {
                events: { call: true, ret: false, exec: false },
                onCallSummary: function(summary) {
                    var calls = [];
                    for (var target in summary) {
                        calls.push({ addr: target, count: summary[target] });
                    }
                    calls.sort(function(a, b) {
                        return parseInt(a.addr, 16) - parseInt(b.addr, 16);
                    });
                    console.log('[STALKER] FUN_146db5d60 (CA) call summary (' + calls.length + ' targets):');
                    for (var i = 0; i < calls.length; i++) {
                        var c = calls[i];
                        var a = ptr(c.addr);
                        if (a.compare(ptr('0x140000000')) >= 0 && a.compare(ptr('0x150000000')) < 0) {
                            var label = '';
                            if (a.equals(addr(0x6e12a60))) label = ' <<< CA decoder (vtable+0x30)';
                            if (a.equals(addr(0x6e19840))) label = ' <<< PA decoder';
                            if (a.equals(addr(0x6e151d0))) label = ' <<< CA handler';
                            if (a.equals(addr(0x6e1cf10))) label = ' <<< PA handler';
                            if (a.equals(addr(0x6e06740))) label = ' <<< TDF init';
                            if (a.equals(addr(0x79ab0f0))) label = ' <<< TDF field reader';
                            if (a.equals(addr(0x6db4be0))) label = ' <<< RPC internal';
                            console.log('  ' + a + ' x' + c.count + label);
                        }
                    }
                }
            });
        }
    },
    onLeave: function(retval) {
        if (rpcTraceForCA) {
            rpcTraceForCA = false;
            Stalker.unfollow(this._tid);
            Stalker.flush();
            console.log('[STALKER] FUN_146db5d60 (CA) trace complete');
        }
    }
});

// ============================================================
// Also trace FUN_146db5d60 for PreAuth for comparison
// ============================================================
var paRpcTraced = false;

Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        var bufStart, bodyLen;
        try {
            bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            bodyLen = bufEnd.sub(bufStart).toInt32();
        } catch(e) { return; }

        if (bodyLen < 4) return;
        try {
            var firstBytes = bufStart.readByteArray(4);
            var arr = new Uint8Array(firstBytes);
            // PreAuth: ANON = 86 eb ee
            if (arr[0] === 0x86 && arr[1] === 0xeb && arr[2] === 0xee && !paRpcTraced) {
                paRpcTraced = true;
                console.log('[STALKER-PA] Starting FULL trace of FUN_146db5d60 for PreAuth...');
                this._tid = Process.getCurrentThreadId();
                this._isPA = true;
                
                Stalker.follow(this._tid, {
                    events: { call: true, ret: false, exec: false },
                    onCallSummary: function(summary) {
                        var calls = [];
                        for (var target in summary) {
                            calls.push({ addr: target, count: summary[target] });
                        }
                        calls.sort(function(a, b) {
                            return parseInt(a.addr, 16) - parseInt(b.addr, 16);
                        });
                        console.log('[STALKER-PA] FUN_146db5d60 (PA) call summary (' + calls.length + ' targets):');
                        for (var i = 0; i < calls.length; i++) {
                            var c = calls[i];
                            var a = ptr(c.addr);
                            if (a.compare(ptr('0x140000000')) >= 0 && a.compare(ptr('0x150000000')) < 0) {
                                var label = '';
                                if (a.equals(addr(0x6e12a60))) label = ' <<< CA decoder';
                                if (a.equals(addr(0x6e19840))) label = ' <<< PA decoder (vtable+0x30)';
                                if (a.equals(addr(0x6e151d0))) label = ' <<< CA handler';
                                if (a.equals(addr(0x6e1cf10))) label = ' <<< PA handler';
                                if (a.equals(addr(0x6e06740))) label = ' <<< TDF init';
                                if (a.equals(addr(0x79ab0f0))) label = ' <<< TDF field reader';
                                if (a.equals(addr(0x6db4be0))) label = ' <<< RPC internal';
                                console.log('  ' + a + ' x' + c.count + label);
                            }
                        }
                    }
                });
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this._isPA) {
            this._isPA = false;
            Stalker.unfollow(this._tid);
            Stalker.flush();
            console.log('[STALKER-PA] FUN_146db5d60 (PA) trace complete');
        }
    }
});

// ============================================================
// Hook the CA handler to see what params it gets
// (after our DLL cave runs, this won't fire — but just in case)
// ============================================================
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[CA-HANDLER] Called! RCX=' + args[0] + ' RDX=' + args[1] + ' R8=' + args[2]);
        }
    });
} catch(e) {
    console.log('[CA-HANDLER] Could not hook (DLL may have patched it): ' + e);
}

console.log('=== Frida v33 Ready ===');
console.log('Will trace FUN_146db5d60 for both PreAuth and CreateAccount');
console.log('This shows the FULL call graph including TDF decode step');
