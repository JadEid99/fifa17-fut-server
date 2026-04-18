// Frida v8: Force the QoS job to complete so the Login callback fires naturally
//
// The Login flow: FUN_146e19720 creates a "qosapi" job at loginSM+0x18.
// The job does QoS probes, then its callback (LAB_146e1d730) sends the
// ACTUAL Login RPC through the BlazeSDK framework (with proper msgId).
// The QoS probes fail because there's no HTTPS QoS server.
// 
// Fix: After the job is created, force its sub-job state to "complete"
// so the callback fires without waiting for QoS.
//
// Also keep the raw SilentLogin send as a backup.

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v8] base: ' + base);

// Get send function from game's stored pointer
var sendFn = null;
var blazeSocket = null;

try {
    var sendPtr = base.add(0x8e22400).readPointer();
    var recvPtr = base.add(0x8e223f8).readPointer();
    sendFn = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int'], 'win64');
    console.log('[v8] send() at ' + sendPtr);

    Interceptor.attach(recvPtr, {
        onEnter: function(args) { this.sock = args[0].toInt32(); this.buf = args[1]; },
        onLeave: function(retval) {
            if (blazeSocket || retval.toInt32() <= 0) return;
            try {
                if (this.buf.add(6).readU8() === 0x00 && this.buf.add(7).readU8() === 0x09) {
                    blazeSocket = this.sock;
                    console.log('[v8] Found Blaze socket: ' + blazeSocket);
                }
            } catch(e) {}
        }
    });
    console.log('[v8] Hooked recv()');
} catch(e) {
    console.log('[v8] Socket setup failed: ' + e);
}

// TDF encoding helpers
function encodeTdfTag(tag) {
    while (tag.length < 4) tag += ' ';
    var c0 = tag.charCodeAt(0) - 0x20, c1 = tag.charCodeAt(1) - 0x20;
    var c2 = tag.charCodeAt(2) - 0x20, c3 = tag.charCodeAt(3) - 0x20;
    return [(c0 << 2) | (c1 >> 4), ((c1 & 0xF) << 4) | (c2 >> 2), ((c2 & 0x3) << 6) | c3];
}
function encodeTdfVarInt(n) {
    var bytes = [], first = true;
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
    var body = [];
    var t = encodeTdfTag('AUTH'); body.push(t[0],t[1],t[2],0x01);
    var s = 'FAKEAUTHCODE1234567890\0';
    var sb = []; for(var i=0;i<s.length;i++) sb.push(s.charCodeAt(i));
    body = body.concat(encodeTdfVarInt(sb.length)).concat(sb);
    t = encodeTdfTag('PID '); body.push(t[0],t[1],t[2],0x00);
    body = body.concat(encodeTdfVarInt(1000000001));
    t = encodeTdfTag('TYPE'); body.push(t[0],t[1],t[2],0x00);
    body = body.concat(encodeTdfVarInt(1));
    var len = body.length;
    var hdr = [(len>>24)&0xFF,(len>>16)&0xFF,(len>>8)&0xFF,len&0xFF,
               0,0, 0,1, 0,0x32,
               (msgId>>16)&0xFF,(msgId>>8)&0xFF,msgId&0xFF,
               0x00, 0,0];
    return hdr.concat(body);
}

var done = false;

// Replace LoginCheck
try {
    Interceptor.replace(base.add(0x6e1dae0), new NativeCallback(function(loginSM) {
        if (done) return 1;
        done = true;

        console.log('[v8] LoginCheck called. loginSM=' + loginSM);

        // Read the job handle at +0x18
        var jobHandle = loginSM.add(0x18).readPointer();
        console.log('[v8] +0x18 job handle = ' + jobHandle);

        if (!jobHandle.isNull()) {
            // The job exists. It has sub-jobs at +0x28 (linked list).
            // Each sub-job has state at +0x30.
            // State 0 = initial, 1 = sending probes, 2 = waiting, 3 = error/complete
            // If we set all sub-job states to 1 (complete/success), the job callback fires.
            console.log('[v8] Attempting to force QoS job completion...');
            try {
                // The job structure: +0x20 = main transport, +0x28 = sub-job list head
                var subjob = jobHandle.add(0x28).readPointer();
                var count = 0;
                while (!subjob.isNull() && count < 5) {
                    var state = subjob.add(0x30).readU32();
                    console.log('[v8] Sub-job ' + count + ' at ' + subjob + ' state=' + state);
                    
                    // Force state to 1 (FUN_1478abfa0 state 1 = send probes + complete)
                    // Actually state 1 calls FUN_1478aa9c0 which sends more probes.
                    // We want the job to think probes succeeded.
                    // Set state to 2 (waiting for response) with a fake success
                    // OR just set the transport ready flag
                    
                    var transport = subjob.add(0x08).readPointer();
                    if (!transport.isNull()) {
                        console.log('[v8] Sub-job transport: ' + transport);
                        // Set the ready flag at transport+0x1088
                        try {
                            transport.add(0x1088).writeU8(1);
                            console.log('[v8] Set transport+0x1088 = 1 (ready)');
                        } catch(e) {
                            console.log('[v8] Cannot write transport flag: ' + e);
                        }
                    }
                    
                    subjob = subjob.readPointer(); // next in linked list
                    count++;
                }
            } catch(e) {
                console.log('[v8] Job manipulation error: ' + e);
            }
        }

        // Also send raw SilentLogin as backup
        if (blazeSocket && sendFn) {
            var pkt = buildSilentLoginPacket(100);
            var buf = Memory.alloc(pkt.length);
            for (var i = 0; i < pkt.length; i++) buf.add(i).writeU8(pkt[i]);
            var r = sendFn(blazeSocket, buf, pkt.length, 0);
            console.log('[v8] Raw SilentLogin sent: ' + r + ' bytes');
        }

        // Check state after delays
        var sm = loginSM;
        setTimeout(function() {
            try {
                var jh = sm.add(0x18).readPointer();
                console.log('[v8] T+2s: +0x18=' + jh);
                if (!jh.isNull()) {
                    var sj = jh.add(0x28).readPointer();
                    if (!sj.isNull()) {
                        console.log('[v8] T+2s: sub-job state=' + sj.add(0x30).readU32());
                    }
                }
            } catch(e) {}
        }, 2000);

        setTimeout(function() {
            try {
                console.log('[v8] T+10s: +0x18=' + sm.add(0x18).readPointer());
            } catch(e) {}
        }, 10000);

        return 1;
    }, 'uint64', ['pointer'], 'win64'));
    console.log('[v8] Replaced LoginCheck');
} catch(e) {
    console.log('[v8] Replace failed: ' + e);
}

console.log('[v8] Ready.');
