/*
 * Frida v19: Hook the raw Blaze frame receive to see what the game reads
 * 
 * Strategy: Hook the recv/read function that feeds data to the Blaze parser.
 * Then hook the RPC response matcher to see how it processes each frame.
 * 
 * Key functions from Ghidra:
 * - FUN_146db2fe0: processes pending RPC responses (takes connection + msgId + error)
 * - FUN_146dbae10: processes incoming frame (dispatches to handler)
 * - FUN_146dbba60: sends outgoing RPC
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v19 - RPC Response Matching Trace ===');

// Hook FUN_146db2fe0 - this is called to complete a pending RPC with a response
// Signature: void FUN_146db2fe0(longlong param_1, undefined4 *param_2, undefined4 param_3)
// param_2 = pointer to msgId/response info, param_3 = error code
Interceptor.attach(addr(0x6db2fe0), {
    onEnter: function(args) {
        var p2 = args[1];
        var p3 = args[2].toInt32();
        try {
            var msgId = p2.readU32();
            console.log('[RPC_COMPLETE] msgId=' + msgId + ' error=0x' + (p3>>>0).toString(16));
        } catch(e) {
            console.log('[RPC_COMPLETE] error=0x' + (p3>>>0).toString(16) + ' (p2 read failed)');
        }
    }
});

// Hook FUN_146dbae10 - processes incoming Blaze frame
// This is where the frame header is parsed and dispatched
Interceptor.attach(addr(0x6dbae10), {
    onEnter: function(args) {
        this.p1 = args[0];
        this.p2 = args[1]; // frame data pointer?
        this.p3 = args[2];
        this.p4 = args[3];
        try {
            // Try to read the frame header from p2 or p3
            var hdr = args[1].readByteArray(16);
            var arr = new Uint8Array(hdr);
            var hex = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log('[FRAME_IN] header: ' + hex);
        } catch(e) {}
    }
});

// Hook FUN_146dbba60 - sends outgoing RPC (to see what the game sends)
Interceptor.attach(addr(0x6dbba60), {
    onEnter: function(args) {
        try {
            // args[1] might be the frame buffer
            var comp = args[1].add(6).readU16();
            var cmd = args[1].add(8).readU16();
            console.log('[FRAME_OUT] comp=0x' + comp.toString(16) + ' cmd=0x' + cmd.toString(16));
        } catch(e) {
            console.log('[FRAME_OUT] (could not read header)');
        }
    }
});

// Hook FUN_146db1880 - processes received data (bool return = success)
Interceptor.attach(addr(0x6db1880), {
    onEnter: function(args) {
        this.p3 = args[2]; // data pointer
        try {
            var data = args[2].readByteArray(16);
            var arr = new Uint8Array(data);
            var hex = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log('[RECV_DATA] first 16 bytes: ' + hex);
        } catch(e) {}
    },
    onLeave: function(ret) {
        console.log('[RECV_DATA] returned: ' + ret);
    }
});

// Hook FUN_146e151d0 - CreateAccount response handler (to confirm it's called)
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p3 = args[2].toInt32();
        console.log('[CA_RESP] param3=0x' + (p3>>>0).toString(16));
    }
});

console.log('=== Ready. Press Q to trigger connection. ===');
