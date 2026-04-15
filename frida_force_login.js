/*
 * Frida v57: INJECT LOGIN TYPE INTO ARRAY
 *
 * v54-v56 findings:
 * - State machine manipulation works but game disconnects anyway
 * - The disconnect is NOT from the state machine — it's from the auth layer
 * - The ROOT CAUSE is: login type array at loginSM+0x218 is EMPTY
 * - FUN_146e1dae0 returns 0 → no Login RPC ever sent → game disconnects
 *
 * v57 strategy — attack the root cause:
 * - Hook FUN_146e1c3f0 (login type processor, called during PreAuth)
 * - AFTER it copies data from PreAuth response (step 1)
 * - INJECT a fake login type entry into the array at param_1+0x218/+0x220
 * - This makes the game think PreAuth contained a login type
 * - FUN_146e1dae0 will iterate the array and call FUN_146e1eb70
 * - FUN_146e1eb70 sends the actual Login RPC with our fake auth code
 * - This happens on the game's main thread — correct context
 *
 * The login type entry structure (0x20 bytes per entry):
 *   +0x00: pointer to string (non-empty = valid entry)
 *   +0x18: pointer to config object
 *     config+0x10: pointer to auth token string
 *     config+0x28: u16 transport type (0=Login)
 *
 * FUN_146e1eb70 checks:
 *   - param_3 != 0 (config object non-null)
 *   - *(char*)*param_2 != '\0' (entry string non-empty)
 *   - *(longlong*)(param_1 + 0x18) != 0 (job handle exists)
 *   - *(char**)(param_3 + 0x10) non-null and non-empty (auth token)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v57: Inject Login Type ===');

// ============================================================
// Step 1: NOP the OSDK screen loader (safety net)
// ============================================================
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
    console.log('[INIT] NOPed FUN_146e00f40');
} catch(e) { console.log('[INIT] NOP error: ' + e); }

// ============================================================
// Step 2: Allocate persistent fake login type entry
// ============================================================
// These must survive beyond the hook — allocate once globally
var fakeEntryStr = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
var fakeAuthToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");

// Login type entry (0x20 bytes)
var fakeEntry = Memory.alloc(0x40);
// entry+0x00 = pointer to non-empty string (checked by FUN_146e1eb70)
fakeEntry.writePointer(fakeEntryStr);
// entry+0x08 through +0x17 = zero padding
fakeEntry.add(0x08).writeU64(0);
fakeEntry.add(0x10).writeU64(0);

// Config object (at fakeEntry+0x20)
var fakeConfig = fakeEntry.add(0x20);
// config+0x00 through +0x0F = zero
fakeConfig.writeU64(0);
fakeConfig.add(0x08).writeU64(0);
// config+0x10 = pointer to auth token string
fakeConfig.add(0x10).writePointer(fakeAuthToken);
// config+0x18 through +0x27 = zero
fakeConfig.add(0x18).writeU64(0);
fakeConfig.add(0x20).writeU64(0);
// config+0x28 = u16 transport type (0 = Login)
fakeConfig.add(0x28).writeU16(0);

// entry+0x18 = pointer to config object
fakeEntry.add(0x18).writePointer(fakeConfig);

// End of array = fakeEntry + 0x20 (one entry of 0x20 bytes)
var fakeEntryEnd = fakeEntry.add(0x20);

console.log('[INIT] Fake login entry at ' + fakeEntry + ', config at ' + fakeConfig);
console.log('[INIT] Auth token at ' + fakeAuthToken + ' = "FAKEAUTHCODE1234567890"');

// ============================================================
// Step 3: Hook FUN_146e1c3f0 — inject login type after PreAuth copy
// ============================================================
var loginTypeInjected = false;

Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        this._param1 = args[0]; // loginSM
        console.log('[LOGIN-TYPES] FUN_146e1c3f0 entered, loginSM=' + args[0]);
    },
    onLeave: function(retval) {
        // This function has already:
        // 1. Copied login type data from PreAuth response
        // 2. Checked BlazeHub+0x53f
        // 3. Counted entries (0)
        // 4. Called FUN_146e19720 (login job creator)
        // 5. Called FUN_146e1dae0 (returned 0 — empty array)
        // 6. Called FUN_146e19b30 (error handler — but patched to NOP?)
        //
        // We can't inject INSIDE this function easily with onEnter/onLeave.
        // We need a different approach — hook FUN_146e1dae0 instead.
        console.log('[LOGIN-TYPES] FUN_146e1c3f0 returned');
    }
});

// ============================================================
// Step 4: Hook FUN_146e1dae0 — inject array BEFORE it checks
// ============================================================
// This is the function that iterates the login type array.
// If we inject our fake entry into the array BEFORE it runs,
// it will find our entry and call FUN_146e1eb70.

Interceptor.attach(addr(0x6e1dae0), {
    onEnter: function(args) {
        var loginSM = args[0];
        this._loginSM = loginSM;
        
        try {
            var arrStart = loginSM.add(0x218).readPointer();
            var arrEnd = loginSM.add(0x220).readPointer();
            var count = arrEnd.sub(arrStart).toInt32() / 0x20;
            console.log('[LOGIN-CHECK] FUN_146e1dae0 entered, array count=' + count);
            
            // Check if job handle exists at +0x18
            var jobHandle = loginSM.add(0x18).readPointer();
            console.log('[LOGIN-CHECK] Job handle (loginSM+0x18) = ' + jobHandle);
            
            if (count === 0 && !loginTypeInjected) {
                loginTypeInjected = true;
                console.log('[LOGIN-CHECK] *** INJECTING fake login type entry! ***');
                
                // Write our fake entry pointers into the array
                loginSM.add(0x218).writePointer(fakeEntry);
                loginSM.add(0x220).writePointer(fakeEntryEnd);
                
                // Verify
                var newStart = loginSM.add(0x218).readPointer();
                var newEnd = loginSM.add(0x220).readPointer();
                var newCount = newEnd.sub(newStart).toInt32() / 0x20;
                console.log('[LOGIN-CHECK] Array now: start=' + newStart + ' end=' + newEnd + ' count=' + newCount);
                
                // Also verify the entry data
                var entryPtr = newStart.readPointer();
                console.log('[LOGIN-CHECK] entry[0] string ptr = ' + entryPtr);
                var entryStr = entryPtr.readUtf8String();
                console.log('[LOGIN-CHECK] entry[0] string = "' + entryStr + '"');
                var configPtr = newStart.add(0x18).readPointer();
                console.log('[LOGIN-CHECK] entry[0] config ptr = ' + configPtr);
                var tokenPtr = configPtr.add(0x10).readPointer();
                console.log('[LOGIN-CHECK] config+0x10 (token) = ' + tokenPtr);
                var tokenStr = tokenPtr.readUtf8String();
                console.log('[LOGIN-CHECK] token = "' + tokenStr + '"');
                var transport = configPtr.add(0x28).readU16();
                console.log('[LOGIN-CHECK] config+0x28 (transport) = ' + transport);
            }
        } catch(e) {
            console.log('[LOGIN-CHECK] Error: ' + e);
        }
    },
    onLeave: function(retval) {
        console.log('[LOGIN-CHECK] FUN_146e1dae0 returned ' + retval);
    }
});

// ============================================================
// Step 5: Redirect CreateAccount→OriginLogin + block Logout
// ============================================================
var blockLogout = false;

Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[WIRE] CreateAccount(0x0A) -> OriginLogin(0x98)');
            this.context.r9 = ptr(0x98);
        }
        if (comp === 1 && cmd === 0x46 && blockLogout) {
            console.log('[WIRE] *** BLOCKING Logout → Ping ***');
            this.context.r8 = ptr(0x9);
            this.context.r9 = ptr(0x2);
        }
    }
});

// ============================================================
// Step 6: Track ALL RPC sends
// ============================================================
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            var cmdNames = {
                0x0A: 'CreateAccount', 0x28: 'Login', 0x32: 'SilentLogin',
                0x3C: 'ExpressLogin', 0x46: 'Logout', 0x98: 'OriginLogin',
                0x07: 'PreAuth', 0x08: 'PostAuth', 0x01: 'FetchClientConfig',
                0x02: 'Ping', 0xF2: 'GetLegalDocsInfo', 0xF6: 'GetTOS',
                0x2F: 'GetPrivacyPolicy', 0x1D: 'ListEntitlements2',
                0x64: 'ListPersonas'
            };
            var name = cmdNames[cmd] || ('0x' + cmd.toString(16));
            console.log('[RPC] comp=0x' + comp.toString(16) + ' cmd=' + name + ' (' + cmd + ')');
        }
    }
});

// ============================================================
// Step 7: CreateAccount handler — still write +0x10/+0x13 + block Logout
// ============================================================
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        console.log('[HANDLER] CreateAccount handler entered');
        blockLogout = true;
        this.context.r8 = ptr(0);
        try {
            var resp = args[1];
            resp.add(0x10).writeU8(1);
            resp.add(0x11).writeU8(0);
            resp.add(0x12).writeU8(0);
            resp.add(0x13).writeU8(0); // 0 = don't trigger state (1,3) — just return cleanly
            console.log('[HANDLER] Wrote +0x10=1, +0x13=0 (no OSDK), R8=0');
        } catch(e) { console.log('[HANDLER] Write error: ' + e); }
    },
    onLeave: function(retval) {
        console.log('[HANDLER] CreateAccount handler returned (no state transition)');
    }
});

// ============================================================
// Step 8: Monitor Login RPC sender
// ============================================================
try {
    Interceptor.attach(addr(0x6e1eb70), {
        onEnter: function(args) {
            console.log('[LOGIN-SEND] *** FUN_146e1eb70 called! ***');
            console.log('[LOGIN-SEND] loginSM=' + args[0] + ' entry=' + args[1] + ' config=' + args[2] + ' param4=' + args[3]);
            try {
                var entry = args[1];
                var config = ptr(args[2]);
                var strPtr = entry.readPointer();
                console.log('[LOGIN-SEND] entry string: "' + strPtr.readUtf8String() + '"');
                var tokenPtr = config.add(0x10).readPointer();
                console.log('[LOGIN-SEND] auth token: "' + tokenPtr.readUtf8String() + '"');
                var transport = config.add(0x28).readU16();
                console.log('[LOGIN-SEND] transport type: ' + transport);
            } catch(e) { console.log('[LOGIN-SEND] read error: ' + e); }
        },
        onLeave: function(retval) {
            console.log('[LOGIN-SEND] returned ' + retval);
        }
    });
} catch(e) {}

// Monitor PostAuth
try {
    Interceptor.attach(addr(0x6e213e0), {
        onEnter: function(args) {
            console.log('[POSTAUTH] *** FUN_146e213e0 called! ***');
        }
    });
} catch(e) {}

// Monitor state transitions
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            var state = args[1].toInt32();
            var p3 = args[2].toInt32();
            console.log('[STATE] transition(' + state + ', ' + p3 + ')');
        }
    });
} catch(e) {}

// Monitor FUN_146e19720 (login job creator)
try {
    Interceptor.attach(addr(0x6e19720), {
        onEnter: function(args) {
            console.log('[LOGIN-START] FUN_146e19720 called');
            // Check +0x18 (job handle) after this returns
            this._loginSM = args[0];
        },
        onLeave: function(retval) {
            try {
                var jh = this._loginSM.add(0x18).readPointer();
                console.log('[LOGIN-START] After: job handle = ' + jh);
            } catch(e) {}
        }
    });
} catch(e) {}

console.log('=== Frida v57 Ready ===');
