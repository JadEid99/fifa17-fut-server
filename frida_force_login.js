/*
 * Frida v60: RAW WINSOCK INTERCEPT
 *
 * Hook ws2_32!send and ws2_32!recv to capture the exact bytes
 * the Origin SDK sends/receives on its TCP socket.
 * This will reveal the actual protocol format.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v60: Raw Winsock Intercept ===');

// ============================================================
// Step 1: NOP OSDK screen
// ============================================================
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
} catch(e) {}

// ============================================================
// Step 2: Hook ws2_32!send — capture all outgoing TCP data
// ============================================================
var ws2 = Module.findBaseAddress('ws2_32.dll');
if (ws2) {
    var sendAddr = Module.findExportByName('ws2_32.dll', 'send');
    var recvAddr = Module.findExportByName('ws2_32.dll', 'recv');
    
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                this._socket = args[0].toInt32();
                this._buf = args[1];
                this._len = args[2].toInt32();
                
                // Only log sends to localhost high ports (Origin SDK)
                // We can't easily filter by port here, so log everything small
                if (this._len > 0 && this._len < 2000) {
                    var data = this._buf.readByteArray(this._len);
                    var bytes = new Uint8Array(data);
                    
                    // Check if it looks like XML (starts with '<')
                    if (bytes[0] === 0x3C || this._len < 100) {
                        var hex = '';
                        for (var i = 0; i < Math.min(bytes.length, 128); i++) {
                            hex += ('0' + bytes[i].toString(16)).slice(-2) + ' ';
                        }
                        var text = '';
                        for (var i = 0; i < Math.min(bytes.length, 200); i++) {
                            text += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
                        }
                        console.log('[SEND] socket=' + this._socket + ' len=' + this._len);
                        console.log('[SEND] hex: ' + hex.substring(0, 200));
                        console.log('[SEND] txt: ' + text);
                    }
                }
            },
            onLeave: function(retval) {
                // Log if send failed
                if (retval.toInt32() < 0) {
                    console.log('[SEND] FAILED socket=' + this._socket + ' ret=' + retval);
                }
            }
        });
        console.log('[INIT] Hooked ws2_32!send at ' + sendAddr);
    }
    
    if (recvAddr) {
        Interceptor.attach(recvAddr, {
            onEnter: function(args) {
                this._socket = args[0].toInt32();
                this._buf = args[1];
                this._len = args[2].toInt32();
            },
            onLeave: function(retval) {
                var bytesRead = retval.toInt32();
                if (bytesRead > 0 && bytesRead < 2000) {
                    var data = this._buf.readByteArray(bytesRead);
                    var bytes = new Uint8Array(data);
                    
                    if (bytes[0] === 0x3C || bytesRead < 100) {
                        var hex = '';
                        for (var i = 0; i < Math.min(bytes.length, 128); i++) {
                            hex += ('0' + bytes[i].toString(16)).slice(-2) + ' ';
                        }
                        var text = '';
                        for (var i = 0; i < Math.min(bytes.length, 200); i++) {
                            text += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
                        }
                        console.log('[RECV] socket=' + this._socket + ' len=' + bytesRead);
                        console.log('[RECV] hex: ' + hex.substring(0, 200));
                        console.log('[RECV] txt: ' + text);
                    }
                }
            }
        });
        console.log('[INIT] Hooked ws2_32!recv at ' + recvAddr);
    }
} else {
    console.log('[INIT] ws2_32.dll not found!');
}

// ============================================================
// Step 3: Hook connect to see what ports are used
// ============================================================
var connectAddr = Module.findExportByName('ws2_32.dll', 'connect');
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            this._socket = args[0].toInt32();
            var sa = args[1];
            var family = sa.readU16();
            if (family === 2) { // AF_INET
                var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                console.log('[CONNECT] socket=' + this._socket + ' -> ' + ip + ':' + port);
            }
        },
        onLeave: function(retval) {
            console.log('[CONNECT] result=' + retval);
        }
    });
    console.log('[INIT] Hooked ws2_32!connect');
}

// ============================================================
// Step 4: Track Blaze RPC sends
// ============================================================
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            var cmdNames = {
                0x0A: 'CreateAccount', 0x28: 'Login', 0x32: 'SilentLogin',
                0x46: 'Logout', 0x98: 'OriginLogin', 0x07: 'PreAuth',
                0x08: 'PostAuth', 0x01: 'FetchClientConfig', 0x02: 'Ping'
            };
            console.log('[RPC] comp=0x' + comp.toString(16) + ' cmd=' + (cmdNames[cmd] || '0x' + cmd.toString(16)));
        }
    }
});

// ============================================================
// Step 5: State transitions
// ============================================================
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] transition(' + args[1].toInt32() + ', ' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

console.log('=== Frida v60 Ready ===');
