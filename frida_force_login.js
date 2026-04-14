/*
 * Frida v29: Read the ACTUAL vtable of the state machine object at rpc+0x20
 * to find the correct advance function address.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v29: State Machine Vtable ===');

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
            console.log('[CA] CreateAccount RPC found');
            
            // The state machine is at rpc+0x20
            var smPtr = rpc.add(0x20).readPointer();
            console.log('[CA] State machine at ' + smPtr);
            
            if (!smPtr.isNull()) {
                var vtable = smPtr.readPointer();
                console.log('[CA] SM vtable = ' + vtable);
                
                // Read all vtable entries (first 16)
                for (var i = 0; i < 16; i++) {
                    try {
                        var entry = vtable.add(i * 8).readPointer();
                        console.log('[CA] vtable[' + i + '] (+0x' + (i*8).toString(16) + ') = ' + entry);
                    } catch(e) { break; }
                }
                
                // Also dump the state machine object itself (first 0x40 bytes)
                var dump = new Uint8Array(smPtr.readByteArray(0x40));
                var hex = Array.from(dump).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                console.log('[CA] SM object dump: ' + hex);
                
                // Now read the HANDLER object — it's what our cave receives as param_1
                // The handler is referenced from the RPC object. Let's find it.
                // In the original code, the RPC framework calls:
                //   (**(code **)*puVar2)(puVar2, 0);
                // where puVar2 is the RPC object. So vtable[0] of the RPC is the handler dispatch.
                // But the handler object itself is different.
                // Let's look at rpc+0x78 which had vtable 0x143891fe8
                var handlerPtr = rpc.add(0x78).readPointer();
                console.log('[CA] Handler candidate at rpc+0x78 = ' + handlerPtr);
                if (!handlerPtr.isNull()) {
                    var hVtable = handlerPtr.readPointer();
                    console.log('[CA] Handler vtable = ' + hVtable);
                    // Dump handler object
                    var hDump = new Uint8Array(handlerPtr.readByteArray(0x40));
                    var hHex = Array.from(hDump).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                    console.log('[CA] Handler dump: ' + hHex);
                    
                    // Check handler+0x08 — is it the state machine?
                    var h08 = handlerPtr.add(0x08).readPointer();
                    console.log('[CA] handler+0x08 = ' + h08);
                    if (h08.equals(smPtr)) {
                        console.log('[CA] >>> handler+0x08 IS the state machine! <<<');
                    }
                }
            }
        }
    }
});

console.log('=== Ready ===');
