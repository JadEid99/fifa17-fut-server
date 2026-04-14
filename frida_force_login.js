/*
 * Frida v30: Read handler+0x08 object's vtable to find the REAL advance function.
 * Also shorten test — no manual connection needed.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v30 ===');

Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var rpc = args[0];
        var errCode = args[1].toInt32();
        var bodyBuf = args[3];
        if (errCode !== 0) return;
        var bufStart = bodyBuf.add(0x08).readPointer();
        var bufEnd = bodyBuf.add(0x18).readPointer();
        var bodyLen = bufEnd.sub(bufStart).toInt32();
        
        if (bodyLen === 22) {
            console.log('[CA] CreateAccount RPC');
            
            // Handler is at rpc+0x78
            var handler = rpc.add(0x78).readPointer();
            // handler+0x08 is the object our cave calls advance on
            var advObj = handler.add(0x08).readPointer();
            console.log('[CA] handler+0x08 (advance target) = ' + advObj);
            
            if (!advObj.isNull()) {
                var advVtable = advObj.readPointer();
                console.log('[CA] advance target vtable = ' + advVtable);
                
                // Read vtable entries
                for (var i = 0; i < 8; i++) {
                    try {
                        var entry = advVtable.add(i * 8).readPointer();
                        console.log('[CA] advVtable[' + i + '] (+0x' + (i*8).toString(16) + ') = ' + entry);
                    } catch(e) { break; }
                }
                
                // Dump the advance target object
                var dump = new Uint8Array(advObj.readByteArray(0x30));
                var hex = Array.from(dump).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                console.log('[CA] advance target dump: ' + hex);
            }
            
            // ALSO: check what param_1 our cave actually receives
            // Our cave replaces FUN_146e151d0. The RPC framework calls it as:
            //   (**(code **)*puVar2)(puVar2, 0);  -- vtable[0] of RPC object
            // So param_1 = RPC object, NOT the handler!
            // Let's verify: rpc vtable[0] should be FUN_146e151d0 (now our cave)
            var rpcVtable = rpc.readPointer();
            var rpcVt0 = rpcVtable.readPointer();
            console.log('[CA] rpc vtable[0] = ' + rpcVt0);
            
            // So our cave receives the RPC object as param_1!
            // param_1[1] = rpc+0x08
            var rpc08 = rpc.add(0x08).readPointer();
            console.log('[CA] rpc+0x08 (what cave reads as param_1[1]) = ' + rpc08);
            if (!rpc08.isNull()) {
                try {
                    var rpc08Vtable = rpc08.readPointer();
                    console.log('[CA] rpc+0x08 vtable = ' + rpc08Vtable);
                    for (var i = 0; i < 4; i++) {
                        var entry = rpc08Vtable.add(i * 8).readPointer();
                        console.log('[CA] rpc08.vtable[' + i + '] = ' + entry);
                    }
                } catch(e) { console.log('[CA] rpc+0x08 read error: ' + e); }
            }
        }
    }
});

console.log('=== Ready ===');
