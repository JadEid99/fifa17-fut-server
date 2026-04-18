// Frida v7: Send Login RPC directly on the Blaze TCP socket
//
// Previous approach (v6): LoginSender queues auth token in QoS job.
// QoS job needs HTTPS probes to complete. HTTPS fails. Login never dispatches.
//
// New approach: Skip LoginSender entirely. Build a raw SilentLogin packet
// and write it directly to the Blaze TCP socket using Winsock send().
// The server already has a working Login handler that returns session data.
//
// SilentLogin packet format (from PocketRelay):
//   Header: 16 bytes [len:4][ext:2][comp:2][cmd:2][msgId:3][type:1][err:2]
//   Body TDF: AUTH(string) + PID(int) + TYPE(int)
//   comp=0x0001, cmd=0x0032, type=0 (request)

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v7] base: ' + base);

// TDF encoding helpers
function encodeTdfTag(tag) {
    while (tag.length < 4) tag += ' ';
    var c0 = tag.charCodeAt(0) - 0x20;
    var c1 = tag.charCodeAt(1) - 0x20;
    var c2 = tag.charCodeAt(2) - 0x20;
    var c3 = tag.charCodeAt(3) - 0x20;
    return [(c0 << 2) | (c1 >> 4), ((c1 & 0xF) << 4) | (c2 >> 2), ((c2 & 0x3) << 6) | c3];
}

function encodeTdfVarInt(n) {
    var bytes = [];
    var first = true;
    do {
        var b = first ? (n & 0x3F) : (n & 0x7F);
        n = first ? (n >> 6) : (n >> 7);
        first = false;
        if (n > 0) b |= 0x80;
        bytes.push(b);
    } while (n > 0);
    return bytes;
}

function buildSilentLoginPacket(msgId) {
    // TDF body: AUTH(string) + PID(int) + TYPE(int)
    var body = [];
    
    // AUTH tag + type 0x01 (string)
    var authTag = encodeTdfTag('AUTH');
    body.push(authTag[0], authTag[1], authTag[2], 0x01);
    var authStr = 'FAKEAUTHCODE1234567890\0';
    var authBytes = [];
    for (var i = 0; i < authStr.length; i++) authBytes.push(authStr.charCodeAt(i));
    body = body.concat(encodeTdfVarInt(authBytes.length));
    body = body.concat(authBytes);
    
    // PID tag + type 0x00 (integer)
    var pidTag = encodeTdfTag('PID ');
    body.push(pidTag[0], pidTag[1], pidTag[2], 0x00);
    body = body.concat(encodeTdfVarInt(1000000001));
    
    // TYPE tag + type 0x00 (integer)  — 1 = SilentLogin
    var typeTag = encodeTdfTag('TYPE');
    body.push(typeTag[0], typeTag[1], typeTag[2], 0x00);
    body = body.concat(encodeTdfVarInt(1));
    
    // Blaze header: 16 bytes
    var len = body.length;
    var header = [
        (len >> 24) & 0xFF, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF,  // length
        0x00, 0x00,                                                                // ext
        0x00, 0x01,                                                                // comp = 0x0001 (Authentication)
        0x00, 0x32,                                                                // cmd = 0x0032 (SilentLogin)
        (msgId >> 16) & 0xFF, (msgId >> 8) & 0xFF, msgId & 0xFF,                  // msgId
        0x00,                                                                      // type=0 (request)
        0x00, 0x00                                                                 // error=0
    ];
    
    return header.concat(body);
}

// Find the Blaze TCP socket by hooking the send function
var blazeSocket = null;
var sendFn = null;

// Get send/recv from game's stored function pointers (Ghidra addresses)
// DAT_148e22400 = send, DAT_148e223f8 = recv, DAT_148e223d8 = connect
try {
    var sendPtr = base.add(0x8e22400).readPointer();
    var recvPtr = base.add(0x8e223f8).readPointer();
    sendFn = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int'], 'win64');
    console.log('[v7] send() at ' + sendPtr);

    Interceptor.attach(recvPtr, {
        onEnter: function(args) { this.sock = args[0].toInt32(); this.buf = args[1]; },
        onLeave: function(retval) {
            if (blazeSocket || retval.toInt32() <= 0) return;
            try {
                if (this.buf.add(6).readU8() === 0x00 && this.buf.add(7).readU8() === 0x09) {
                    blazeSocket = this.sock;
                    console.log('[v7] Found Blaze socket: ' + blazeSocket);
                }
            } catch(e) {}
        }
    });
    console.log('[v7] Hooked recv() at ' + recvPtr);
} catch(e) {
    console.log('[v7] Socket setup failed: ' + e);
}

// Replace LoginCheck — when called, send Login directly on the socket
var sent = false;
try {
    Interceptor.replace(base.add(0x6e1dae0), new NativeCallback(function(loginSM) {
        if (sent) return 1;
        
        console.log('[v7] LoginCheck called. blazeSocket=' + blazeSocket);
        
        if (!blazeSocket || !sendFn) {
            console.log('[v7] No socket or send function — cannot send Login');
            return 0;
        }
        
        // Build SilentLogin packet with msgId=100 (unused by game)
        var pktBytes = buildSilentLoginPacket(100);
        var pktBuf = Memory.alloc(pktBytes.length);
        for (var i = 0; i < pktBytes.length; i++) {
            pktBuf.add(i).writeU8(pktBytes[i]);
        }
        
        console.log('[v7] Sending SilentLogin packet (' + pktBytes.length + ' bytes) on socket ' + blazeSocket);
        var result = sendFn(blazeSocket, pktBuf, pktBytes.length, 0);
        console.log('[v7] send() returned: ' + result);
        
        if (result > 0) {
            console.log('[v7] >>> SILENTLOGIN SENT ON WIRE! <<<');
            sent = true;
        } else {
            console.log('[v7] send() failed');
        }
        
        return 1;
    }, 'uint64', ['pointer'], 'win64'));
    console.log('[v7] Replaced LoginCheck');
} catch(e) {
    console.log('[v7] Replace failed: ' + e);
}

console.log('[v7] Ready. Waiting for Blaze connection + PreAuth...');
