/*
 * Frida v61: HOOK SDK CONNECT + CAPTURE PROTOCOL
 *
 * The Origin SDK uses TCP but the connection fails because port 4216
 * has nothing listening. We hook the SDK's own connect function
 * (FUN_14712ca40) and redirect it to our server on 3216.
 * Also capture all XML send/recv to understand the protocol.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v61: Hook SDK Connect ===');

// NOP OSDK screen
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
} catch(e) {}

// ============================================================
// Hook the game's connect() function pointer
// The game stores connect at DAT_148e22400 area
// But we can also hook the SDK's connect wrapper FUN_14712ca40
// ============================================================
Interceptor.attach(addr(0x712ca40), {
    onEnter: function(args) {
        // param_4 is the port (u16) at args[3]
        var port = args[3].toInt32() & 0xFFFF;
        console.log('[SDK-CONNECT] Connecting on port ' + port);
        
        // Redirect to our Origin IPC server on port 3216
        if (port !== 10041 && port !== 42230 && port !== 8080 && port !== 17502) {
            console.log('[SDK-CONNECT] *** REDIRECTING port ' + port + ' -> 3216 ***');
            // param_4 is passed as a u16 value, we change it
            args[3] = ptr(3216);
        }
    },
    onLeave: function(retval) {
        console.log('[SDK-CONNECT] result=' + retval);
    }
});
console.log('[INIT] Hooked SDK connect (FUN_14712ca40)');

// ============================================================
// Hook XML send to capture outgoing messages
// ============================================================
Interceptor.attach(addr(0x70e6ee0), {
    onEnter: function(args) {
        try {
            var xmlStr = args[1].readUtf8String();
            console.log('[XML-SEND] ' + xmlStr);
        } catch(e) {}
    }
});
console.log('[INIT] Hooked XML send');

// ============================================================
// Hook raw send/recv via game function pointers
// ============================================================
try {
    var gameSend = addr(0x8e22400).readPointer();
    var gameRecv = addr(0x8e223f8).readPointer();
    console.log('[PTRS] send=' + gameSend + ' recv=' + gameRecv);
    
    if (!gameSend.isNull()) {
        Interceptor.attach(gameSend, {
            onEnter: function(args) {
                this._len = args[2].toInt32();
                if (this._len > 0 && this._len < 2000) {
                    var data = args[1].readByteArray(this._len);
                    var bytes = new Uint8Array(data);
                    var txt = '';
                    for (var i = 0; i < Math.min(bytes.length, 300); i++) {
                        txt += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
                    }
                    if (txt.indexOf('LSX') !== -1 || txt.indexOf('xml') !== -1 || txt.indexOf('<') !== -1) {
                        console.log('[RAW-SEND] len=' + this._len + ': ' + txt);
                    }
                }
            }
        });
        console.log('[INIT] Hooked raw send');
    }
    
    if (!gameRecv.isNull()) {
        Interceptor.attach(gameRecv, {
            onEnter: function(args) {
                this._buf = args[1];
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0 && n < 2000) {
                    var data = this._buf.readByteArray(n);
                    var bytes = new Uint8Array(data);
                    var txt = '';
                    for (var i = 0; i < Math.min(bytes.length, 300); i++) {
                        txt += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
                    }
                    if (txt.indexOf('LSX') !== -1 || txt.indexOf('xml') !== -1 || txt.indexOf('<') !== -1 || n < 50) {
                        console.log('[RAW-RECV] len=' + n + ': ' + txt);
                    }
                }
            }
        });
        console.log('[INIT] Hooked raw recv');
    }
} catch(e) { console.log('[PTRS] Error: ' + e); }

// ============================================================
// Track Blaze RPCs
// ============================================================
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

// State transitions
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] transition(' + args[1].toInt32() + ', ' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

console.log('=== Frida v61 Ready ===');
