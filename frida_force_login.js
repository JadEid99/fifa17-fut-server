/*
 * Frida v60c: RAW WINSOCK INTERCEPT — no arrow functions
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }

function hexDump(bytes, max) {
    var h = '';
    for (var i = 0; i < Math.min(bytes.length, max || 80); i++) {
        h += ('0' + bytes[i].toString(16)).slice(-2) + ' ';
    }
    return h;
}
function textDump(bytes, max) {
    var t = '';
    for (var i = 0; i < Math.min(bytes.length, max || 200); i++) {
        t += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
    }
    return t;
}

console.log('=== Frida v60c: Raw Winsock Intercept ===');

// NOP OSDK screen
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
} catch(e) {}

// Find Winsock functions — use getExportByName with try/catch
var sendAddr = null, recvAddr = null, connectAddr = null;
try { sendAddr = Module.getExportByName('WS2_32.dll', 'send'); } catch(e) {}
try { if (!sendAddr) sendAddr = Module.getExportByName('ws2_32.dll', 'send'); } catch(e) {}
try { recvAddr = Module.getExportByName('WS2_32.dll', 'recv'); } catch(e) {}
try { if (!recvAddr) recvAddr = Module.getExportByName('ws2_32.dll', 'recv'); } catch(e) {}
try { connectAddr = Module.getExportByName('WS2_32.dll', 'connect'); } catch(e) {}
try { if (!connectAddr) connectAddr = Module.getExportByName('ws2_32.dll', 'connect'); } catch(e) {}
console.log('[WINSOCK] send=' + sendAddr + ' recv=' + recvAddr + ' connect=' + connectAddr);

// Also try game's own function pointers
try {
    var gs = addr(0x8e22400).readPointer();
    var gr = addr(0x8e223f8).readPointer();
    var gc = addr(0x8e223d8).readPointer();
    console.log('[GAME-PTRS] send=' + gs + ' recv=' + gr + ' connect=' + gc);
    if (!sendAddr && !gs.isNull()) sendAddr = gs;
    if (!recvAddr && !gr.isNull()) recvAddr = gr;
    if (!connectAddr && !gc.isNull()) connectAddr = gc;
} catch(e) { console.log('[GAME-PTRS] ' + e); }

if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            this._s = args[0].toInt32();
            this._len = args[2].toInt32();
            if (this._len > 0 && this._len < 2000) {
                var data = args[1].readByteArray(this._len);
                var bytes = new Uint8Array(data);
                console.log('[SEND] s=' + this._s + ' len=' + this._len);
                console.log('[SEND] hex: ' + hexDump(bytes));
                console.log('[SEND] txt: ' + textDump(bytes));
            }
        }
    });
    console.log('[INIT] Hooked send');
}

if (recvAddr) {
    Interceptor.attach(recvAddr, {
        onEnter: function(args) {
            this._s = args[0].toInt32();
            this._buf = args[1];
        },
        onLeave: function(retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 2000) {
                var data = this._buf.readByteArray(n);
                var bytes = new Uint8Array(data);
                console.log('[RECV] s=' + this._s + ' len=' + n);
                console.log('[RECV] hex: ' + hexDump(bytes));
                console.log('[RECV] txt: ' + textDump(bytes));
            }
        }
    });
    console.log('[INIT] Hooked recv');
}

if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            this._s = args[0].toInt32();
            try {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8()+'.'+sa.add(5).readU8()+'.'+sa.add(6).readU8()+'.'+sa.add(7).readU8();
                    console.log('[CONNECT] s=' + this._s + ' -> ' + ip + ':' + port);
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            console.log('[CONNECT] result=' + retval);
        }
    });
    console.log('[INIT] Hooked connect');
}

// Track Blaze RPCs
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            var names = {0x0A:'CreateAccount',0x28:'Login',0x32:'SilentLogin',0x46:'Logout',0x98:'OriginLogin',0x07:'PreAuth',0x08:'PostAuth',0x01:'FetchClientConfig',0x02:'Ping'};
            console.log('[RPC] comp=0x'+comp.toString(16)+' cmd='+(names[cmd]||'0x'+cmd.toString(16)));
        }
    }
});

console.log('=== Frida v60c Ready ===');
