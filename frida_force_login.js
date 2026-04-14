/*
 * Frida v31: Dump the state object returned by vtable+0xb8 of the handler.
 * Find a path from the state object to the Login state machine.
 * Also dump the handler object more thoroughly.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v31 ===');

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
            
            // State machine at rpc+0x20
            var sm = rpc.add(0x20).readPointer();
            console.log('[CA] State machine = ' + sm);
            
            // Handler at rpc+0x78
            var handler = rpc.add(0x78).readPointer();
            console.log('[CA] Handler = ' + handler);
            
            // Call vtable+0xb8 on handler to get state object
            // We can't call it from Frida, but we can find it by looking at
            // what the cave would return. The vtable+0xb8 function likely
            // returns a fixed object. Let's look at the handler's vtable.
            var hVtable = handler.readPointer();
            var vt0xb8 = hVtable.add(0xb8).readPointer();
            console.log('[CA] handler.vtable+0xb8 = ' + vt0xb8);
            
            // Dump handler more thoroughly (0x80 bytes)
            var hDump = new Uint8Array(handler.readByteArray(0x80));
            console.log('[CA] Handler full dump:');
            for (var off = 0; off < 0x80; off += 8) {
                var val = handler.add(off).readPointer();
                var label = '';
                if (val.equals(sm)) label = ' <<< STATE MACHINE';
                // Check if it's a game code pointer
                if (val.compare(ptr('0x140000000')) > 0 && val.compare(ptr('0x150000000')) < 0) {
                    label = ' (code)';
                }
                console.log('  +0x' + off.toString(16) + ' = ' + val + label);
            }
            
            // Also scan the state machine object for the handler reference
            console.log('[CA] SM scan for handler ref:');
            for (var off = 0; off < 0x100; off += 8) {
                try {
                    var val = sm.add(off).readPointer();
                    if (val.equals(handler)) {
                        console.log('  SM+0x' + off.toString(16) + ' = handler!');
                    }
                } catch(e) { break; }
            }
        }
    }
});

console.log('=== Ready ===');
