/*
 * Frida v62: REAL ORIGIN PROTOCOL CAPTURE
 * 
 * Origin is running on the PC. We let the game talk to the REAL Origin
 * and capture every byte sent/received to learn the exact protocol.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }

function hexDump(bytes, max) {
    var h = '';
    for (var i = 0; i < Math.min(bytes.length, max || 128); i++) {
        h += ('0' + bytes[i].toString(16)).slice(-2) + ' ';
    }
    return h;
}
function textDump(bytes, max) {
    var t = '';
    for (var i = 0; i < Math.min(bytes.length, max || 300); i++) {
        t += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
    }
    return t;
}

console.log('=== Frida v62: Real Origin Protocol Capture ===');

// Hook game's own send/recv function pointers
try {
    var gameSend = addr(0x8e22400).readPointer();
    var gameRecv = addr(0x8e223f8).readPointer();
    var gameConnect = addr(0x8e223d8).readPointer();
    console.log('[PTRS] send=' + gameSend + ' recv=' + gameRecv + ' connect=' + gameConnect);
    
    if (!gameSend.isNull()) {
        Interceptor.attach(gameSend, {
            onEnter: function(args) {
                this._s = args[0].toInt32();
                this._len = args[2].toInt32();
                if (this._len > 0 && this._len < 5000) {
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
    
    if (!gameRecv.isNull()) {
        Interceptor.attach(gameRecv, {
            onEnter: function(args) {
                this._s = args[0].toInt32();
                this._buf = args[1];
                this._maxLen = args[2].toInt32();
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0 && n < 5000) {
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
    
    if (!gameConnect.isNull()) {
        Interceptor.attach(gameConnect, {
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
} catch(e) { console.log('[PTRS] Error: ' + e); }

console.log('=== Frida v62 Ready — keep Origin open! ===');
