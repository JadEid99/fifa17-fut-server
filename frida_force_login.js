/*
 * Frida v20: Hook Winsock recv to see raw bytes from server
 * Also hook ProtoSSL recv to see decrypted data
 * This is the most reliable way to see what the game actually receives
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v20 - Raw Socket Trace ===');

// Hook Winsock recv to see raw TCP data
var ws2 = Module.findBaseAddress('ws2_32.dll');
if (ws2) {
    var recvAddr = Module.findExportByName('ws2_32.dll', 'recv');
    if (recvAddr) {
        Interceptor.attach(recvAddr, {
            onEnter: function(args) {
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function(ret) {
                var n = ret.toInt32();
                if (n > 0 && n <= 2048) {
                    var data = this.buf.readByteArray(Math.min(n, 64));
                    var arr = new Uint8Array(data);
                    var hex = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
                    console.log('[RECV] ' + n + ' bytes: ' + hex);
                }
            }
        });
        console.log('[HOOK] Winsock recv hooked at ' + recvAddr);
    }
    
    var sendAddr = Module.findExportByName('ws2_32.dll', 'send');
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                var n = args[2].toInt32();
                if (n > 0 && n <= 2048) {
                    var data = args[1].readByteArray(Math.min(n, 64));
                    var arr = new Uint8Array(data);
                    var hex = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
                    console.log('[SEND] ' + n + ' bytes: ' + hex);
                }
            }
        });
        console.log('[HOOK] Winsock send hooked at ' + sendAddr);
    }
}

// Hook CreateAccount response handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p3 = args[2].toInt32();
        console.log('[CA_RESP] param3=0x' + (p3>>>0).toString(16));
    }
});

console.log('=== Ready ===');
