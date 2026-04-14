/*
 * Frida v25: Trace the ACTUAL TDF decode call in FUN_146db5d60
 * The decode happens at: (*(param_3->vtable + 0x18))(param_3, param_4, lVar4, 0)
 * where param_4 = body buffer, lVar4 = response object
 *
 * Also hook the vtable+0x30 call to see what it returns.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v25: TDF Decode Deep Trace ===');

// Hook FUN_146db5d60 to trace the decode flow
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var rpc = args[0];
        var errCode = args[1].toInt32();
        var stream = args[2];
        var bodyBuf = args[3];
        
        this.rpc = rpc;
        this.stream = stream;
        this.bodyBuf = bodyBuf;
        this.errCode = errCode;
        
        if (errCode === 0) {
            // Read body buffer
            var bufStart = bodyBuf.add(0x08).readPointer();
            var bufEnd = bodyBuf.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            console.log('[DECODE] err=0 bodyLen=' + bodyLen);
            
            if (bodyLen > 0 && bodyLen < 200) {
                var hex = Array.from(new Uint8Array(bufStart.readByteArray(bodyLen)))
                    .map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                console.log('[DECODE] body: ' + hex);
            }
            
            // Read rpc[0xe] (offset 0x70) — pre-existing decoder
            var preDecoder = rpc.add(0x70).readPointer();
            console.log('[DECODE] rpc[0xe]=' + preDecoder);
            
            // Read the vtable to see what vtable+0x30 points to
            var vtable = rpc.readPointer();
            var decodeFn = vtable.add(0x30).readPointer();
            console.log('[DECODE] vtable+0x30 -> ' + decodeFn);
            
            // Read stream vtable to see what vtable+0x18 points to
            var streamVtable = stream.readPointer();
            var streamDecodeFn = streamVtable.add(0x18).readPointer();
            console.log('[DECODE] stream.vtable+0x18 -> ' + streamDecodeFn);
        }
    },
    onLeave: function(retval) {
        if (this.errCode === 0) {
            // Check rpc[0xc] (offset 0x60) — the response object after decode
            var respObj = this.rpc.add(0x60).readPointer();
            console.log('[DECODE] after: respObj=' + respObj);
            if (!respObj.isNull()) {
                try {
                    var d = new Uint8Array(respObj.readByteArray(0x20));
                    var hex = Array.from(d).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                    console.log('[DECODE] respObj dump: ' + hex);
                } catch(e) {}
            }
            
            // Check if body buffer was consumed (read position advanced)
            var bufStart = this.bodyBuf.add(0x08).readPointer();
            var bufCur = this.bodyBuf.add(0x10).readPointer();
            var consumed = bufCur.sub(bufStart).toInt32();
            console.log('[DECODE] body consumed: ' + consumed + ' bytes');
        }
    }
});

// Hook the stream decode function — this is where TDF parsing actually happens
// We need to find the address dynamically from the vtable
var streamDecodeHooked = false;
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        if (streamDecodeHooked) return;
        if (args[1].toInt32() !== 0) return;
        
        var stream = args[2];
        var streamVtable = stream.readPointer();
        var decodeFnAddr = streamVtable.add(0x18).readPointer();
        
        if (decodeFnAddr.toInt32() > 0x140000000) {
            console.log('[HOOK] Hooking stream decode at ' + decodeFnAddr);
            Interceptor.attach(decodeFnAddr, {
                onEnter: function(a) {
                    console.log('[STREAM-DECODE] called with: stream=' + a[0] + ' buf=' + a[1] + ' resp=' + a[2] + ' arg4=' + a[3]);
                    this.resp = a[2];
                    this.buf = a[1];
                },
                onLeave: function(ret) {
                    console.log('[STREAM-DECODE] returned');
                    if (this.resp && !this.resp.isNull()) {
                        try {
                            var d = new Uint8Array(this.resp.readByteArray(0x20));
                            var hex = Array.from(d).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                            console.log('[STREAM-DECODE] resp after: ' + hex);
                        } catch(e) {}
                    }
                    // Check buffer consumption
                    if (this.buf) {
                        try {
                            var bufStart = this.buf.add(0x08).readPointer();
                            var bufCur = this.buf.add(0x10).readPointer();
                            console.log('[STREAM-DECODE] buf consumed: ' + bufCur.sub(bufStart).toInt32());
                        } catch(e) {}
                    }
                }
            });
            streamDecodeHooked = true;
        }
    }
});

console.log('=== Ready ===');
