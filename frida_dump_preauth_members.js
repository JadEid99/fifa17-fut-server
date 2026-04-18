// Frida v5: INJECT login type entry into loginSM+0x218/+0x220
//
// ROOT CAUSE: The QOSS wrapper's internal vector at +0x60 is empty.
// The TDF copy skips it (member-by-member copy, not memcpy).
// loginSM+0x218/+0x220 stays at default zeros.
//
// SOLUTION: After the TDF copy, write a login type entry into the
// destination vector at loginSM+0x218/+0x220. Use the EXISTING
// template entry from loginSM+0xE0 (which has proper vtables).
//
// The entry at +0xE0 has:
//   vtable=0x143888ff8, flags=0x80000000, type=4, inner_vtable=0x143888ea8
//
// We allocate a 0x20-byte copy of this entry, then set the vector
// pointers: start=entry, end=entry+0x20 (1 entry).

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v5] base: ' + base);

var injected = false;

// Hook FUN_146e1c1f0 — called AFTER the TDF copy, BEFORE the loop
// This is the perfect injection point
try {
    Interceptor.attach(base.add(0x6e1c1f0), {
        onLeave: function(retval) {
            if (injected) return;

            var loginSM = this.context.rcx;  // param_1 = loginSM (first arg, in rcx on x64)
            console.log('[v5] FUN_146e1c1f0 returned. loginSM=' + loginSM);

            // Read the template entry at loginSM+0xE0
            try {
                var templatePtr = loginSM.add(0xE0).readPointer();
                console.log('[v5] Template entry at +0xE0: ' + templatePtr);

                if (templatePtr.isNull()) {
                    console.log('[v5] Template is NULL — cannot inject');
                    return;
                }

                // Read the template (first 0x40 bytes for safety)
                var templateBytes = templatePtr.readByteArray(0x40);
                var tArr = new Uint8Array(templateBytes);
                var hex = '';
                for (var i = 0; i < Math.min(0x40, tArr.length); i++) {
                    hex += ('0' + tArr[i].toString(16)).slice(-2) + ' ';
                    if ((i+1) % 16 === 0) hex += '\n  ';
                }
                console.log('[v5] Template bytes:\n  ' + hex);

                // Allocate memory for ONE entry (0x20 bytes)
                var entry = Memory.alloc(0x20);
                console.log('[v5] Allocated entry at: ' + entry);

                // Copy the template's first 0x20 bytes to our entry
                Memory.copy(entry, templatePtr, 0x20);
                console.log('[v5] Copied template to entry');

                // Verify the copy
                var copyBytes = entry.readByteArray(0x20);
                var cArr = new Uint8Array(copyBytes);
                hex = '';
                for (var i = 0; i < cArr.length; i++) {
                    hex += ('0' + cArr[i].toString(16)).slice(-2) + ' ';
                }
                console.log('[v5] Entry bytes: ' + hex);

                // Set the vector pointers at loginSM+0x218 and +0x220
                var vecStart = loginSM.add(0x218);
                var vecEnd = loginSM.add(0x220);

                console.log('[v5] Before: +0x218=' + vecStart.readPointer() + ' +0x220=' + vecEnd.readPointer());

                vecStart.writePointer(entry);
                vecEnd.writePointer(entry.add(0x20));

                console.log('[v5] After:  +0x218=' + vecStart.readPointer() + ' +0x220=' + vecEnd.readPointer());
                console.log('[v5] Injected 1 login type entry!');

                injected = true;

            } catch(e) {
                console.log('[v5] Injection error: ' + e);
            }
        }
    });
    console.log('[v5] Hooked FUN_146e1c1f0 (injection point)');
} catch(e) {
    console.log('[v5] Hook error: ' + e);
}

// Hook LoginCheck to see if it now finds entries
try {
    Interceptor.attach(base.add(0x6e1c3f0), {
        onEnter: function(args) {
            console.log('[v5] LoginTypesProcessor entered');
        },
        onLeave: function(retval) {
            console.log('[v5] LoginTypesProcessor returned');
        }
    });
} catch(e) {}

// Hook PreAuth handler for timing
try {
    Interceptor.attach(base.add(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[v5] PreAuth handler entered, err=' + args[2].toInt32());
        }
    });
} catch(e) {}

// Monitor RPC sends to see if Login appears on the wire
try {
    Interceptor.attach(base.add(0x6df0e80), {
        onEnter: function(args) {
            try {
                var comp = this.context.r9.toInt32() & 0xFFFF;
                var cmd = (this.context.r9.toInt32() >> 16) & 0xFFFF;
                // Only log auth-related RPCs
                if (comp === 1 || comp === 9) {
                    console.log('[v5] RPC SEND comp=0x' + comp.toString(16) + ' cmd=0x' + cmd.toString(16));
                }
            } catch(e) {}
        }
    });
} catch(e) {
    console.log('[v5] RPC hook failed (non-critical): ' + e);
}

console.log('[v5] Ready. Waiting for PreAuth...');
