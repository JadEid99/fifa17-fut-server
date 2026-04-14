/*
 * Frida v22: Trace RPC dispatch + pending lookup + CreateAccount handler
 * to see exactly why the response isn't matching.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v22: RPC Trace ===');

// FUN_146db5a60 — RPC response dispatcher
// Called when any Blaze packet arrives. Parses the header and routes by type.
Interceptor.attach(addr(0x6db5a60), {
    onEnter: function(args) {
        // args[0] = this/connection, args[1] = packet buffer pointer
        var p1 = args[1];
        if (!p1.isNull()) {
            // Read the 16-byte header
            var hdr = p1.readByteArray(16);
            var bytes = new Uint8Array(hdr);
            var comp = (bytes[6] << 8) | bytes[7];
            var cmd = (bytes[8] << 8) | bytes[9];
            var msgIdHi = bytes[10];
            var msgIdMid = bytes[11];
            var msgIdLo = bytes[12];
            var typeByte = bytes[13];
            var errHi = bytes[14];
            var errLo = bytes[15];
            var msgType = (typeByte >> 5) & 7;
            var msgId = (msgIdHi << 16) | (msgIdMid << 8) | msgIdLo;
            
            // Only log Auth component (0x0001) to reduce noise
            if (comp === 1) {
                console.log('[DISPATCH] comp=0x' + comp.toString(16) + ' cmd=0x' + cmd.toString(16) +
                    ' msgId=' + msgId + ' type=' + msgType + ' byte13=0x' + typeByte.toString(16) +
                    ' err=0x' + ((errHi << 8) | errLo).toString(16));
                console.log('[DISPATCH] raw hdr: ' + 
                    Array.from(bytes).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' '));
            }
        }
    }
});

// FUN_146db5030 — RPC pending lookup
// Searches pending RPCs for a match. Returns pointer or NULL.
Interceptor.attach(addr(0x6db5030), {
    onEnter: function(args) {
        this.p1 = args[0]; // connection/list
        this.p2 = args[1]; // match param 1 (component+command?)
        this.p3 = args[2]; // match param 2 (msgId?)
        console.log('[LOOKUP] enter: p1=' + this.p1 + ' p2=0x' + this.p2.toString(16) + ' p3=0x' + this.p3.toString(16));
    },
    onLeave: function(retval) {
        console.log('[LOOKUP] result: ' + (retval.isNull() ? 'NULL (no match!)' : retval.toString()));
    }
});

// FUN_146db9270 — RPC response matcher (uses XOR & 0xf7ffffff)
Interceptor.attach(addr(0x6db9270), {
    onEnter: function(args) {
        this.p1 = args[0];
        this.p2 = args[1];
        this.p3 = args[2];
        console.log('[MATCHER] enter: p1=' + this.p1 + ' p2=0x' + this.p2.toString(16) + ' p3=0x' + this.p3.toString(16));
    },
    onLeave: function(retval) {
        console.log('[MATCHER] result: ' + retval);
    }
});

// FUN_146e151d0 — CreateAccount response handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[CA] param3=0x' + (p3>>>0).toString(16) + (p3===0?' SUCCESS':' ERROR'));
        if (p3 === 0 && !p2.isNull()) {
            console.log('[CA] +0x10 userId=' + p2.add(0x10).readU32());
            console.log('[CA] +0x13 byte=' + p2.add(0x13).readU8());
            try {
                var pnam = p2.add(0x18).readPointer();
                console.log('[CA] +0x18 pnam_ptr=' + pnam);
                if (!pnam.isNull() && pnam.toInt32() > 0x1000) {
                    console.log('[CA] pnam="' + pnam.readUtf8String(32) + '"');
                }
            } catch(e) {}
        }
    }
});

console.log('=== Ready ===');
