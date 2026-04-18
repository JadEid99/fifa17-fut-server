// Frida v6: Replace LoginCheck to call LoginSender with proper job handle
//
// Previous approach (v5): Inject entry into +0x218/+0x220 array
//   Result: Crashes because tracking array at +0x38 isn't resized
//
// New approach: Don't touch the array. Instead, replace FUN_146e1dae0
// (LoginCheck) entirely. Our replacement:
//   1. Reads +0x18 (job handle) — if non-zero, calls LoginSender
//   2. If +0x18 is zero, returns 0 (same as original)
//
// LoginSender (FUN_146e1eb70) needs:
//   param_1 = loginSM
//   param_2 = entry pointer (we use the template at +0xE0)
//   param_3 = config pointer (*(entry+0x18)) — we create one with auth token
//   param_4 = 1
//
// LoginSender checks: param_3 != 0 AND +0x18 != 0
// If both true, it sends the Login RPC on the wire.

'use strict';

var base = null;
try { base = Module.findBaseAddress('FIFA17.exe'); } catch(e) {}
if (!base) {
    try { base = Process.enumerateModules()[0].base; } catch(e2) { base = ptr(0x140000000); }
}
console.log('[v6] base: ' + base);

var loginSenderAddr = base.add(0x6e1eb70);
var loginSenderFn = new NativeFunction(loginSenderAddr, 'uint64', ['pointer', 'pointer', 'pointer', 'int'], 'win64');

// Create the config object once (persistent allocation)
var config = Memory.alloc(0x40);
var authToken = Memory.allocUtf8String('FAKEAUTHCODE1234567890');
config.add(0x10).writePointer(authToken);
config.add(0x28).writeU16(1);  // transport type 1 = SilentLogin
console.log('[v6] Config object at ' + config + ' auth token at ' + authToken);

var replaced = false;

// Replace LoginCheck (FUN_146e1dae0)
try {
    Interceptor.replace(base.add(0x6e1dae0), new NativeCallback(function(loginSM) {
        if (replaced) {
            // Already ran once — return 0 to prevent re-entry
            return 0;
        }
        replaced = true;

        console.log('[v6] LoginCheck REPLACED. loginSM=' + loginSM);

        // Check job handle at +0x18
        var jobHandle = loginSM.add(0x18).readPointer();
        console.log('[v6] +0x18 job handle = ' + jobHandle);

        if (jobHandle.isNull()) {
            console.log('[v6] No job handle — LoginSender would fail. Returning 0.');
            return 0;
        }

        // Read the template entry at +0xE0
        var templateEntry = loginSM.add(0xE0).readPointer();
        console.log('[v6] Template entry at +0xE0 = ' + templateEntry);

        if (templateEntry.isNull()) {
            console.log('[v6] No template entry. Returning 0.');
            return 0;
        }

        // Call LoginSender: FUN_146e1eb70(loginSM, entry, config, 1)
        console.log('[v6] Calling LoginSender...');
        try {
            var result = loginSenderFn(loginSM, templateEntry, config, 1);
            console.log('[v6] LoginSender returned: ' + result);
            if (result != 0) {
                console.log('[v6] >>> LOGIN RPC SENT! <<<');
            }
        } catch(e) {
            console.log('[v6] LoginSender error: ' + e);
        }

        // Schedule state checks
        setTimeout(function() {
            try {
                console.log('[v6] T+3s: +0x18=' + loginSM.add(0x18).readPointer());
            } catch(e) {}
        }, 3000);

        return 1;  // Tell caller "login was sent"
    }, 'uint64', ['pointer'], 'win64'));
    console.log('[v6] Replaced LoginCheck at ' + base.add(0x6e1dae0));
} catch(e) {
    console.log('[v6] Replace failed: ' + e);
}

// Only hook FUN_146e1c1f0 for injection — no other hooks
console.log('[v6] Ready. Waiting for PreAuth...');
