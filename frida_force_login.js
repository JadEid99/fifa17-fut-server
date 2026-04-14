/*
 * Frida v23: Deep trace of CreateAccount response processing
 * Focus: Does the TDF body data reach the decoder? What does the decoder produce?
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v23: TDF Decode Trace ===');

// FUN_146db5d60 — Called after RPC match found. This is where TDF decoding happens.
// param_1 = pending RPC object, param_2 = error code, param_3 = stream obj, param_4 = body buffer
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var rpc = args[0];
        var errCode = args[1].toInt32();
        var stream = args[2];
        var bodyBuf = args[3];
        
        // Read the body buffer structure: [+0x00]=allocator, [+0x08]=start, [+0x10]=end, [+0x18]=capacity
        var bufStart = bodyBuf.add(0x08).readPointer();
        var bufEnd = bodyBuf.add(0x10).readPointer();
        var bodyLen = bufEnd.sub(bufStart).toInt32();
        
        console.log('[RPC-DECODE] err=' + errCode + ' bodyLen=' + bodyLen + ' bufStart=' + bufStart);
        
        if (bodyLen > 0 && bodyLen < 4096) {
            var bodyData = bufStart.readByteArray(bodyLen);
            var bytes = new Uint8Array(bodyData);
            var hex = Array.from(bytes).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
            console.log('[RPC-DECODE] body hex: ' + hex);
        }
        
        // Read vtable of the RPC object to identify what type it is
        var vtable = rpc.readPointer();
        console.log('[RPC-DECODE] rpc vtable=' + vtable);
        
        // Read rpc[0xe] (offset 0x70) — pre-existing decoder check
        var preDecoder = rpc.add(0x70).readPointer();
        console.log('[RPC-DECODE] rpc[0xe] (pre-decoder)=' + preDecoder);
        
        this.rpc = rpc;
        this.errCode = errCode;
    },
    onLeave: function(retval) {
        // After decode, check what's at rpc[0xc] (offset 0x60) — the decoded response object
        var respObj = this.rpc.add(0x60).readPointer();
        console.log('[RPC-DECODE] after: rpc[0xc] (resp obj)=' + respObj);
        if (!respObj.isNull() && respObj.toInt32() > 0x1000) {
            try {
                // Read the response structure — offsets 0x10-0x13 are the UID field
                console.log('[RPC-DECODE] resp+0x10=' + respObj.add(0x10).readU32());
                console.log('[RPC-DECODE] resp+0x13=' + respObj.add(0x13).readU8());
                // Check if PNAM string was decoded at +0x18
                var pnamPtr = respObj.add(0x18).readPointer();
                console.log('[RPC-DECODE] resp+0x18 (pnam ptr)=' + pnamPtr);
            } catch(e) { console.log('[RPC-DECODE] resp read err: ' + e); }
        }
    }
});

// FUN_146e151d0 — CreateAccount response handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p1 = args[0];
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[CA] param2=' + p2 + ' param3=0x' + (p3>>>0).toString(16) + (p3===0?' SUCCESS':' ERROR'));
        if (!p2.isNull()) {
            console.log('[CA] +0x10=' + p2.add(0x10).readU32() + ' +0x11=' + p2.add(0x11).readU8() + 
                ' +0x12=' + p2.add(0x12).readU8() + ' +0x13=' + p2.add(0x13).readU8());
            // Dump first 0x20 bytes of param2 to see the full structure
            var data = p2.readByteArray(0x28);
            var bytes = new Uint8Array(data);
            var hex = Array.from(bytes).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
            console.log('[CA] param2 dump: ' + hex);
        }
    }
});

// FUN_146dbe710 — Buffer init (creates the body buffer from raw data)
// This is called right before FUN_146db5d60
Interceptor.attach(addr(0x6dbe710), {
    onEnter: function(args) {
        this.outBuf = args[0];
        this.srcPtr = args[1];
        this.srcLen = args[2];
        var len = args[2].toInt32();
        console.log('[BUF-INIT] outBuf=' + args[0] + ' src=' + args[1] + ' len=' + len);
        if (len > 0 && len < 4096) {
            var data = args[1].readByteArray(Math.min(len, 64));
            var bytes = new Uint8Array(data);
            var hex = Array.from(bytes).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
            console.log('[BUF-INIT] data: ' + hex);
        }
    }
});

console.log('=== Ready ===');
