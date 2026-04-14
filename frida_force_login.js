/*
 * Frida v27: Hook our DLL cave to see what param_1[1] actually is
 * and what the vtable+0x08 call does.
 * 
 * Our cave is at a dynamically allocated address. We can find it by
 * hooking FUN_146e151d0 (which is now a JMP to our cave).
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v27: Cave Runtime Trace ===');

// Read the cave address from the patched FUN_146e151d0
// The patch is: MOV RAX, cave_addr (48 B8 xx xx xx xx xx xx xx xx) / JMP RAX (FF E0)
var patchSite = addr(0x6e151d0);
var byte0 = patchSite.readU8();
console.log('[INIT] FUN_146e151d0 byte0=0x' + byte0.toString(16));

if (byte0 === 0x48) {
    // Patched — read the cave address
    var caveAddr = patchSite.add(2).readPointer();
    console.log('[INIT] Cave at ' + caveAddr);
    
    // Hook the cave entry to trace param_1
    Interceptor.attach(caveAddr, {
        onEnter: function(args) {
            var param1 = args[0]; // RCX = param_1
            console.log('[CAVE] param_1=' + param1);
            
            try {
                // Read param_1[1] (offset 0x08)
                var p1_1 = param1.add(0x08).readPointer();
                console.log('[CAVE] param_1[1]=' + p1_1);
                
                if (!p1_1.isNull()) {
                    // Read vtable of param_1[1]
                    var vtable = p1_1.readPointer();
                    console.log('[CAVE] param_1[1].vtable=' + vtable);
                    
                    // Read vtable+0x08
                    var advanceFn = vtable.add(0x08).readPointer();
                    console.log('[CAVE] vtable+0x08=' + advanceFn);
                    
                    // Dump first 8 vtable entries
                    for (var i = 0; i < 8; i++) {
                        var entry = vtable.add(i * 8).readPointer();
                        console.log('[CAVE] vtable[' + i + '] = ' + entry);
                    }
                    
                    // Dump param_1 object (first 0x40 bytes)
                    var dump = new Uint8Array(param1.readByteArray(0x40));
                    var hex = Array.from(dump).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' ');
                    console.log('[CAVE] param_1 dump: ' + hex);
                }
            } catch(e) {
                console.log('[CAVE] Error: ' + e);
            }
        }
    });
} else {
    console.log('[INIT] FUN_146e151d0 NOT patched (byte0 != 0x48)');
    // Hook the original function
    Interceptor.attach(patchSite, {
        onEnter: function(args) {
            console.log('[CA-ORIG] param1=' + args[0] + ' param2=' + args[1] + ' param3=' + args[2]);
        }
    });
}

// Also hook FUN_146e1c3f0 (Login type processor)
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[LOGIN-PROC] CALLED!');
    }
});

console.log('=== Ready ===');
