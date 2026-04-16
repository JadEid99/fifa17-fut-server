/*
 * Frida v62b: Hook ws2_32.dll directly using known base address
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
    for (var i = 0; i < Math.min(bytes.length, max || 500); i++) {
        t += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : '.';
    }
    return t;
}

console.log('=== Frida v62b: WS2_32 Direct Hook ===');

// Find ws2_32 module
var ws2 = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase() === 'ws2_32.dll') {
        ws2 = m;
        console.log('[WS2] Found: ' + m.name + ' at ' + m.base + ' size=' + m.size);
    }
});

if (ws2) {
    // Find exports by enumerating
    var sendAddr = null, recvAddr = null, connectAddr = null;
    ws2.enumerateExports().forEach(function(exp) {
        if (exp.name === 'send') sendAddr = exp.address;
        if (exp.name === 'recv') recvAddr = exp.address;
        if (exp.name === 'connect') connectAddr = exp.address;
    });
    
    console.log('[WS2] send=' + sendAddr + ' recv=' + recvAddr + ' connect=' + connectAddr);
    
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                this._s = args[0].toInt32();
                this._len = args[2].toInt32();
                if (this._len > 0 && this._len < 5000) {
                    var data = args[1].readByteArray(this._len);
                    var bytes = new Uint8Array(data);
                    var txt = textDump(bytes);
                    // Only log if it contains XML or interesting data
                    if (txt.indexOf('<') !== -1 || txt.indexOf('LSX') !== -1 || this._len < 50) {
                        console.log('[WS2-SEND] s=' + this._s + ' len=' + this._len);
                        console.log('[WS2-SEND] hex: ' + hexDump(bytes, 64));
                        console.log('[WS2-SEND] txt: ' + txt);
                    }
                }
            }
        });
        console.log('[INIT] Hooked ws2_32!send');
    }
    
    if (recvAddr) {
        Interceptor.attach(recvAddr, {
            onEnter: function(args) {
                this._s = args[0].toInt32();
                this._buf = args[1];
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0 && n < 5000) {
                    var data = this._buf.readByteArray(n);
                    var bytes = new Uint8Array(data);
                    var txt = textDump(bytes);
                    if (txt.indexOf('<') !== -1 || txt.indexOf('LSX') !== -1 || n < 50) {
                        console.log('[WS2-RECV] s=' + this._s + ' len=' + n);
                        console.log('[WS2-RECV] hex: ' + hexDump(bytes, 64));
                        console.log('[WS2-RECV] txt: ' + txt);
                    }
                }
            }
        });
        console.log('[INIT] Hooked ws2_32!recv');
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
                        console.log('[WS2-CONNECT] s=' + this._s + ' -> ' + ip + ':' + port);
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('[WS2-CONNECT] result=' + retval);
            }
        });
        console.log('[INIT] Hooked ws2_32!connect');
    }
} else {
    console.log('[WS2] ws2_32.dll NOT FOUND');
}

console.log('=== Frida v62b Ready — keep Origin open! ===');
