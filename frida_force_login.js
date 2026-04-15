/*
 * Frida v32: Deep trace of TDF decoders to find why CreateAccount fails.
 *
 * Key addresses (no ASLR, base=0x140000000):
 *   0x146db5d60 - RPC response decoder (dispatches to vtable+0x30)
 *   0x146e19840 - PreAuth decoder (WORKS)
 *   0x146e12a60 - CreateAccount decoder (FAILS)
 *   0x146e12a00 - FetchClientConfig decoder (FAILS)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v32: TDF Decoder Deep Trace ===');
console.log('Base: ' + base);

// ============================================================
// Hook 1: FUN_146db5d60 — RPC response decoder
// This is called after RPC matching succeeds.
// Args: rpc(RCX), errCode(EDX), ???(R8), bodyBuf(R9)
// ============================================================
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

        var handler, handlerVtable;
        try {
            handler = rpc.add(0x78).readPointer();
            handlerVtable = handler.readPointer();
        } catch(e) {
            handler = ptr(0);
            handlerVtable = ptr(0);
        }

        console.log('\n[RPC-DECODE] errCode=' + errCode + ' bodyLen=' + bodyLen +
                    ' handler=' + handler + ' vtable=' + handlerVtable);

        if (bodyLen > 0 && bodyLen < 10000) {
            var bodyBytes = bufStart.readByteArray(bodyLen);
            var hex = '';
            var arr = new Uint8Array(bodyBytes);
            for (var i = 0; i < Math.min(arr.length, 128); i++) {
                hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                if ((i + 1) % 32 === 0) hex += '\n  ';
            }
            console.log('[RPC-DECODE] Body hex (' + bodyLen + 'b):\n  ' + hex);
        }

        // Dump the bodyBuf object structure (it's a TDF reader/buffer)
        try {
            console.log('[RPC-DECODE] bodyBuf object dump:');
            for (var off = 0; off < 0x40; off += 8) {
                var val = bodyBufObj.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
        } catch(e) {}
    }
});

// ============================================================
// Hook 2: CreateAccount decoder at 0x146e12a60
// ============================================================
Interceptor.attach(addr(0x6e12a60), {
    onEnter: function(args) {
        console.log('\n[CA-DECODER] === ENTERED ===');
        console.log('[CA-DECODER] RCX(this)=' + this.context.rcx);
        console.log('[CA-DECODER] RDX=' + this.context.rdx);
        console.log('[CA-DECODER] R8=' + this.context.r8);
        console.log('[CA-DECODER] R9=' + this.context.r9);

        // Dump the response object (this/RCX) BEFORE decode
        try {
            var obj = this.context.rcx;
            console.log('[CA-DECODER] Response object BEFORE:');
            for (var off = 0; off < 0x60; off += 8) {
                var val = obj.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
        } catch(e) {}

        // Dump arg2 (RDX) — this is likely the TDF reader
        try {
            var reader = this.context.rdx;
            console.log('[CA-DECODER] TDF reader (RDX):');
            var readerVtable = reader.readPointer();
            console.log('  vtable = ' + readerVtable);
            for (var off = 0; off < 0x40; off += 8) {
                var val = reader.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
            // If the reader has buffer pointers, dump the buffer content
            // Typical TDF reader: +0x08 = current pos, +0x10 = end pos
            var pos = reader.add(0x08).readPointer();
            var end = reader.add(0x10).readPointer();
            if (pos.compare(ptr(0)) > 0 && end.compare(pos) > 0) {
                var remaining = end.sub(pos).toInt32();
                console.log('[CA-DECODER] Reader buffer: pos=' + pos + ' end=' + end + ' remaining=' + remaining);
                if (remaining > 0 && remaining < 1000) {
                    var bufBytes = pos.readByteArray(Math.min(remaining, 64));
                    var hex = '';
                    var arr = new Uint8Array(bufBytes);
                    for (var i = 0; i < arr.length; i++) {
                        hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                    }
                    console.log('[CA-DECODER] Buffer content: ' + hex);
                }
            }
        } catch(e) {
            console.log('[CA-DECODER] Reader dump error: ' + e);
        }

        this._obj = this.context.rcx;
    },
    onLeave: function(retval) {
        console.log('[CA-DECODER] === RETURNED === ret=' + retval);
        try {
            var obj = this._obj;
            console.log('[CA-DECODER] Response object AFTER:');
            for (var off = 0; off < 0x60; off += 8) {
                var val = obj.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
        } catch(e) {}
    }
});

// ============================================================
// Hook 3: PreAuth decoder at 0x146e19840 (for comparison)
// ============================================================
Interceptor.attach(addr(0x6e19840), {
    onEnter: function(args) {
        console.log('\n[PA-DECODER] === ENTERED ===');
        console.log('[PA-DECODER] RCX(this)=' + this.context.rcx);
        console.log('[PA-DECODER] RDX=' + this.context.rdx);

        // Dump the TDF reader for comparison
        try {
            var reader = this.context.rdx;
            console.log('[PA-DECODER] TDF reader (RDX):');
            var readerVtable = reader.readPointer();
            console.log('  vtable = ' + readerVtable);
            for (var off = 0; off < 0x40; off += 8) {
                var val = reader.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
            var pos = reader.add(0x08).readPointer();
            var end = reader.add(0x10).readPointer();
            if (pos.compare(ptr(0)) > 0 && end.compare(pos) > 0) {
                var remaining = end.sub(pos).toInt32();
                console.log('[PA-DECODER] Reader buffer: pos=' + pos + ' end=' + end + ' remaining=' + remaining);
                if (remaining > 0 && remaining < 1000) {
                    var bufBytes = pos.readByteArray(Math.min(remaining, 64));
                    var hex = '';
                    var arr = new Uint8Array(bufBytes);
                    for (var i = 0; i < arr.length; i++) {
                        hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                    }
                    console.log('[PA-DECODER] Buffer content: ' + hex);
                }
            }
        } catch(e) {
            console.log('[PA-DECODER] Reader dump error: ' + e);
        }
    },
    onLeave: function(retval) {
        console.log('[PA-DECODER] === RETURNED === ret=' + retval);
    }
});

// ============================================================
// Hook 4: FetchClientConfig decoder at 0x146e12a00
// ============================================================
Interceptor.attach(addr(0x6e12a00), {
    onEnter: function(args) {
        console.log('\n[FCC-DECODER] === ENTERED ===');
        console.log('[FCC-DECODER] RCX=' + this.context.rcx + ' RDX=' + this.context.rdx);
    },
    onLeave: function(retval) {
        console.log('[FCC-DECODER] === RETURNED === ret=' + retval);
    }
});

// ============================================================
// Hook 5: The CreateAccount response handler FUN_146e151d0
// This is PATCHED by the DLL cave. Let's hook the cave entry
// to see what happens after the decoder runs.
// ============================================================
// We can't hook the original since it's overwritten by the DLL.
// Instead, let's hook the function that CALLS the decoder.

// ============================================================
// Hook 6: Trace the TDF tag reader function
// In BlazeSDK, TdfDecoder::readField() reads 3-byte tag + 1-byte type.
// This is likely a function in the 0x146e0xxxx range.
// Let's find it by hooking common TDF read patterns.
//
// The TDF reader likely has these functions:
//   readTag() - reads 3 bytes, decodes to 4-char tag
//   readType() - reads 1 byte type
//   readVarInt() - reads variable-length integer
//   readString() - reads length + string bytes
//
// These are called by the decoder. Let's use Stalker to trace
// the first call to the CA decoder.
// ============================================================

var caTraced = false;
Interceptor.attach(addr(0x6e12a60), {
    onEnter: function(args) {
        if (caTraced) return;
        caTraced = true;
        
        console.log('[STALKER] Tracing CA decoder execution...');
        var tid = Process.getCurrentThreadId();
        
        Stalker.follow(tid, {
            events: { call: true, ret: false, exec: false },
            onCallSummary: function(summary) {
                var calls = [];
                for (var target in summary) {
                    calls.push({ addr: target, count: summary[target] });
                }
                calls.sort(function(a, b) {
                    return parseInt(a.addr, 16) - parseInt(b.addr, 16);
                });
                console.log('[STALKER] CA decoder call summary (' + calls.length + ' unique targets):');
                for (var i = 0; i < calls.length; i++) {
                    var c = calls[i];
                    var a = ptr(c.addr);
                    // Only show game code (0x140000000 - 0x150000000)
                    if (a.compare(ptr('0x140000000')) >= 0 && a.compare(ptr('0x150000000')) < 0) {
                        console.log('  ' + a + ' x' + c.count);
                    }
                }
            }
        });
    },
    onLeave: function(retval) {
        if (!caTraced) return;
        Stalker.unfollow(Process.getCurrentThreadId());
        Stalker.flush();
        console.log('[STALKER] CA decoder trace complete');
    }
});

// Also trace PreAuth decoder for comparison
var paTraced = false;
Interceptor.attach(addr(0x6e19840), {
    onEnter: function(args) {
        if (paTraced) return;
        paTraced = true;
        
        console.log('[STALKER-PA] Tracing PreAuth decoder execution...');
        var tid = Process.getCurrentThreadId();
        
        Stalker.follow(tid, {
            events: { call: true, ret: false, exec: false },
            onCallSummary: function(summary) {
                var calls = [];
                for (var target in summary) {
                    calls.push({ addr: target, count: summary[target] });
                }
                calls.sort(function(a, b) {
                    return parseInt(a.addr, 16) - parseInt(b.addr, 16);
                });
                console.log('[STALKER-PA] PreAuth decoder call summary (' + calls.length + ' unique targets):');
                for (var i = 0; i < calls.length; i++) {
                    var c = calls[i];
                    var a = ptr(c.addr);
                    if (a.compare(ptr('0x140000000')) >= 0 && a.compare(ptr('0x150000000')) < 0) {
                        console.log('  ' + a + ' x' + c.count);
                    }
                }
            }
        });
    },
    onLeave: function(retval) {
        if (!paTraced) return;
        Stalker.unfollow(Process.getCurrentThreadId());
        Stalker.flush();
        console.log('[STALKER-PA] PreAuth decoder trace complete');
    }
});

console.log('=== Frida v32 Ready ===');
console.log('Hooks: RPC decoder, CA decoder, PA decoder, FCC decoder, Stalker traces');
console.log('Waiting for game...');
