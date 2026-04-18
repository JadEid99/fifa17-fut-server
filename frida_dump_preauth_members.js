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
        onEnter: function(args) {
            this.loginSM = args[0];  // save param_1 before it gets clobbered
        },
        onLeave: function(retval) {
            if (injected) return;

            var loginSM = this.loginSM;
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

                // The entry at +0x18 is read by LoginCheck as *(entry+0x18) = config ptr
                // LoginSender reads config+0x10 = auth token string, config+0x28 = transport type
                // The template has a vtable at +0x18, not a config pointer.
                // We need to create a config object and point entry+0x18 to it.
                var config = Memory.alloc(0x40);
                // Write auth token string at config+0x10
                var authToken = Memory.allocUtf8String('FAKEAUTHCODE1234567890');
                config.add(0x10).writePointer(authToken);
                // Write transport type at config+0x28 (0 = Login, 1 = SilentLogin, 2 = OriginLogin)
                config.add(0x28).writeU16(1);  // SilentLogin
                // Point entry+0x18 to our config
                entry.add(0x18).writePointer(config);
                console.log('[v5] Created config object at ' + config + ' with auth token and transport=1');

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

                // Also reset the one-shot flag at loginSM+0x18
                // FUN_146e19720 checks this and returns if non-zero.
                // The DLL's background LOGIN-INJECT may have already set it.
                loginSM.add(0x18).writePointer(ptr(0));
                console.log('[v5] Reset +0x18 one-shot flag to 0');

                console.log('[v5] After:  +0x218=' + vecStart.readPointer() + ' +0x220=' + vecEnd.readPointer());
                console.log('[v5] Injected 1 login type entry!');

                // Schedule delayed state check — 5 seconds after injection
                var savedSM = loginSM;
                setTimeout(function() {
                    try {
                        var s218 = savedSM.add(0x218).readPointer();
                        var s220 = savedSM.add(0x220).readPointer();
                        var s18 = savedSM.add(0x18).readPointer();
                        console.log('[v5] STATE CHECK (T+5s):');
                        console.log('  +0x218=' + s218 + ' +0x220=' + s220);
                        console.log('  +0x18 (job handle)=' + s18);
                        console.log('  +0x10 (login started)=' + savedSM.add(0x10).readU8());
                        // Check if LoginFallback was called by reading +0x1a3
                        console.log('  +0x1a3=' + savedSM.add(0x1a3).readU8());
                    } catch(e) {
                        console.log('[v5] STATE CHECK error: ' + e);
                    }
                }, 5000);

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

// NO hooks on LoginCheck/LoginSender/LoginFallback — they cause crashes (test 12-13 pattern)
// Instead, use setTimeout to check state AFTER the flow completes
console.log('[v5] No diagnostic hooks (they corrupt call stack). Using delayed state check instead.');

// Hook PreAuth handler for timing
try {
    Interceptor.attach(base.add(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[v5] PreAuth handler entered, err=' + args[2].toInt32());
        }
    });
} catch(e) {}

// Monitor RPC sends — parse the 16-byte Blaze header from the raw socket data
// Hook the actual wire send to detect Login/CreateAccount/Logout
try {
    Interceptor.attach(base.add(0x6df0e80), {
        onEnter: function(args) {
            // Read component and command from the function's parameters
            // FUN_146df0e80 params are complex — just log that it was called
            console.log('[v5] RPC SEND called');
        }
    });
} catch(e) {}

// After injection, schedule a delayed check to see what happened
// This runs 5 seconds after injection, outside any game call stack

console.log('[v5] Ready. Waiting for PreAuth...');
