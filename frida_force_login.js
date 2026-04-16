/*
 * Frida v60b: RAW WINSOCK INTERCEPT — find send/recv across all modules
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v60b: Raw Winsock Intercept ===');

// NOP OSDK screen
try { Memory.patchCode(addr(0x6e00f40), 4, function(c) { new X86Writer(c, {pc:addr(0x6e00f40)}).putRet(); }); } catch(e) {}

// List all modules to find ws2_32
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('ws2') !== -1 || m.name.toLowerCase().indexOf('sock') !== -1 || m.name.toLowerCase().indexOf('winsock') !== -1) {
        console.log('[MODULE] ' + m.name + ' at ' + m.base);
    }
});

// Try multiple ways to find send/recv
var sendAddr = Module.findExportByName('ws2_32.dll', 'send')
            || Module.findExportByName('WS2_32.dll', 'send')
            || Module.findExportByName('WS2_32.DLL', 'send')
            || Module.findExportByName(null, 'send');
var recvAddr = Module.findExportByName('ws2_32.dll', 'recv')
            || Module.findExportByName('WS2_32.dll', 'recv')
            || Module.findExportByName('WS2_32.DLL', 'recv')
            || Module.findExportByName(null, 'recv');
var connectAddr = Module.findExportByName('ws2_32.dll', 'connect')
               || Module.findExportByName(null, 'connect');

console.log('[WINSOCK] send=' + sendAddr + ' recv=' + recvAddr + ' connect=' + connectAddr);

// Also read the game's function pointers directly
try {
    var gameSend = addr(0x8e22400).readPointer();
    var gameRecv = addr(0x8e223f8).readPointer();
    var gameConnect = addr(0x8e223d8).readPointer();
    console.log('[GAME-PTRS] send=' + gameSend + ' recv=' + gameRecv + ' connect=' + gameConnect);
    
    // Use the game's own function pointers — these are guaranteed to be the right ones
    if (!gameSend.isNull()) sendAddr = gameSend;
    if (!gameRecv.isNull()) recvAddr = gameRecv;
    if (!gameConnect.isNull()) connectAddr = gameConnect;
    console.log('[USING] send=' + sendAddr + ' recv=' + recvAddr + ' connect=' + connectAddr);
} catch(e) {
    console.log('[GAME-PTRS] Error: ' + e);
}

if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            this._s = args[0].toInt32();
            this._buf = args[1];
            this._len = args[2].toInt32();
            if (this._len > 0 && this._len < 2000) {
                var data = this._buf.readByteArray(this._len);
                var bytes = new Uint8Array(data);
                var hex = Array.from(bytes).slice(0, 80).map(b => ('0'+b.toString(16)).slice(-2)).join(' ');
                var txt = Array.from(bytes).slice(0, 200).map(b => b>=32&&b<127?String.fromCharCode(b):'.').join('');
                console.log('[SEND] s=' + this._s + ' len=' + this._len + ' hex: ' + hex);
                console.log('[SEND] txt: ' + txt);
            }
        }
    });
    console.log('[INIT] Hooked send at ' + sendAddr);
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
                var hex = Array.from(bytes).slice(0, 80).map(b => ('0'+b.toString(16)).slice(-2)).join(' ');
                var txt = Array.from(bytes).slice(0, 200).map(b => b>=32&&b<127?String.fromCharCode(b):'.').join('');
                console.log('[RECV] s=' + this._s + ' len=' + n + ' hex: ' + hex);
                console.log('[RECV] txt: ' + txt);
            }
        }
    });
    console.log('[INIT] Hooked recv at ' + recvAddr);
}

if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            this._s = args[0].toInt32();
            var sa = args[1];
            try {
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
    console.log('[INIT] Hooked connect at ' + connectAddr);
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

console.log('=== Frida v60b Ready ===');
