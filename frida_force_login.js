/*
 * Frida v59: ORIGIN IPC SIMULATOR
 *
 * v58 revealed:
 * - Origin SDK uses LSX XML format over TCP on localhost
 * - Port is at originSDK+0x35c (was 4216 — set by DLL's fake SDK object)
 * - First message: <LSX><Request recipient="" id="10"><GetSetting SettingId="ENVIRONMENT" version="3"/></Request></LSX>
 * - Patch 3 intercepts FUN_1470db3c0 BEFORE it can call SendXml
 * - Game sends CreateAccount because it never goes through Origin's proper auth flow
 *
 * v59 strategy:
 * - Run a fake Origin TCP server on port 3216 (origin-ipc-server.mjs)
 * - Patch originSDK+0x35c to port 3216
 * - Let FUN_1470db3c0 run naturally (undo Patch 3's body replacement)
 * - The game will call SendXml → our server responds with auth code
 * - Game processes auth code through normal Origin flow → SilentLogin
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v59: Origin IPC Simulator ===');

var ORIGIN_PORT = 3216; // Must match origin-ipc-server.mjs

// ============================================================
// Step 1: NOP OSDK screen (safety net)
// ============================================================
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
    console.log('[INIT] NOPed FUN_146e00f40');
} catch(e) {}

// ============================================================
// Step 2: Patch Origin SDK port to point to our server
// ============================================================
try {
    var sdkPtr = addr(0x4b7c7a0).readPointer();
    console.log('[SDK] Origin SDK object = ' + sdkPtr);
    if (!sdkPtr.isNull()) {
        var oldPort = sdkPtr.add(0x35c).readU16();
        console.log('[SDK] Old port: ' + oldPort);
        sdkPtr.add(0x35c).writeU16(ORIGIN_PORT);
        var newPort = sdkPtr.add(0x35c).readU16();
        console.log('[SDK] New port: ' + newPort + ' (patched to ' + ORIGIN_PORT + ')');
    } else {
        console.log('[SDK] SDK object is NULL — will patch later');
    }
} catch(e) { console.log('[SDK] Port patch error: ' + e); }

// ============================================================
// Step 3: Hook all XML communication
// ============================================================
try {
    Interceptor.attach(addr(0x70e6ee0), {
        onEnter: function(args) {
            try {
                var xmlStr = args[1].readUtf8String();
                console.log('[XML-SEND] ' + xmlStr);
            } catch(e) {
                console.log('[XML-SEND] (could not read)');
            }
        }
    });
    console.log('[INIT] Hooked XML send');
} catch(e) {}

// ============================================================
// Step 4: Hook TCP connect to log connection attempts
// ============================================================
try {
    Interceptor.attach(addr(0x712ca40), {
        onEnter: function(args) {
            var port = args[3].toInt32() & 0xFFFF;
            console.log('[TCP] Connecting to Origin on port ' + port);
        },
        onLeave: function(retval) {
            console.log('[TCP] Connect result: ' + retval);
        }
    });
    console.log('[INIT] Hooked TCP connect');
} catch(e) {}

// ============================================================
// Step 5: Hook RequestAuthCode to see if it reaches SendXml
// ============================================================
try {
    Interceptor.attach(addr(0x70db3c0), {
        onEnter: function(args) {
            console.log('[AUTH-REQ] FUN_1470db3c0 called');
            // Check if the function body is still our DLL's patch or original
            var firstByte = addr(0x70db3c0).readU8();
            console.log('[AUTH-REQ] First byte of function: 0x' + firstByte.toString(16));
            // DLL Patch 3 writes: MOV RAX, imm64 (0x48 0xB8 ...)
            // Original starts with different bytes
            if (firstByte === 0x48) {
                console.log('[AUTH-REQ] WARNING: DLL Patch 3 is active — function body replaced');
                console.log('[AUTH-REQ] The fake auth code will be returned, not Origin SendXml');
            }
        }
    });
    console.log('[INIT] Hooked RequestAuthCode');
} catch(e) {}

// ============================================================
// Step 6: Hook SendXml (FUN_1470e67f0) — bypass user ID check
// Error 0xa2000003 = param_2==0 or param_2 != SDK+0x3a0
// Both userId and SDK+0x3a0 are 0. We need to set both to non-zero.
// ============================================================
try {
    Interceptor.attach(addr(0x70e67f0), {
        onEnter: function(args) {
            console.log('[SENDXML] Auth SendXml called');
            try {
                var sdkObj = args[0];
                var userId = args[1];
                console.log('[SENDXML] userId=' + userId + ' SDK+0x3a0=' + sdkObj.add(0x3a0).readPointer());
                
                // Both are 0 — set both to a fake non-zero value
                if (userId.isNull()) {
                    var fakeId = ptr(33068179); // 0x1F8B4B3
                    args[1] = fakeId;
                    sdkObj.add(0x3a0).writePointer(fakeId);
                    console.log('[SENDXML] *** FIXED: set userId and SDK+0x3a0 to ' + fakeId + ' ***');
                }
                
                if (!args[2].isNull()) {
                    try { console.log('[SENDXML] type="' + args[2].readUtf8String() + '"'); } catch(e) {}
                }
            } catch(e) { console.log('[SENDXML] error: ' + e); }
        },
        onLeave: function(retval) {
            console.log('[SENDXML] returned ' + retval);
        }
    });
    console.log('[INIT] Hooked SendXml with ID bypass');
} catch(e) {}

// ============================================================
// Step 7: Track RPC sends
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
                0x02: 'Ping'
            };
            var name = cmdNames[cmd] || ('0x' + cmd.toString(16));
            console.log('[RPC] comp=0x' + comp.toString(16) + ' cmd=' + name);
        }
    }
});

// ============================================================
// Step 8: Monitor state transitions
// ============================================================
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] transition(' + args[1].toInt32() + ', ' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

// ============================================================
// Step 9: LOGIN TYPE INJECTION (from v57) — the key breakthrough
// Inject a fake login type entry into the array BEFORE FUN_146e1dae0 iterates it
// ============================================================
var fakeEntryStr = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
var fakeAuthToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
var fakeEntry = Memory.alloc(0x40);
fakeEntry.writePointer(fakeEntryStr);
fakeEntry.add(0x08).writeU64(0);
fakeEntry.add(0x10).writeU64(0);
var fakeConfig = fakeEntry.add(0x20);
fakeConfig.writeU64(0);
fakeConfig.add(0x08).writeU64(0);
fakeConfig.add(0x10).writePointer(fakeAuthToken);
fakeConfig.add(0x18).writeU64(0);
fakeConfig.add(0x20).writeU64(0);
fakeConfig.add(0x28).writeU16(0); // transport type 0 = Login
fakeEntry.add(0x18).writePointer(fakeConfig);
var fakeEntryEnd = fakeEntry.add(0x20);
var loginTypeInjected = false;

try {
    Interceptor.attach(addr(0x6e1dae0), {
        onEnter: function(args) {
            var loginSM = args[0];
            try {
                var arrStart = loginSM.add(0x218).readPointer();
                var arrEnd = loginSM.add(0x220).readPointer();
                var count = arrEnd.sub(arrStart).toInt32() / 0x20;
                console.log('[LOGIN-CHECK] array count=' + count);
                
                if (count === 0 && !loginTypeInjected) {
                    loginTypeInjected = true;
                    loginSM.add(0x218).writePointer(fakeEntry);
                    loginSM.add(0x220).writePointer(fakeEntryEnd);
                    console.log('[LOGIN-CHECK] *** INJECTED fake login type! ***');
                }
            } catch(e) { console.log('[LOGIN-CHECK] error: ' + e); }
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CHECK] returned ' + retval);
        }
    });
} catch(e) {}

// Also block Logout after CreateAccount
var blockLogout = false;
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        console.log('[HANDLER] CreateAccount handler entered');
        blockLogout = true;
        this.context.r8 = ptr(0);
        try {
            args[1].add(0x10).writeU8(1);
            args[1].add(0x13).writeU8(0); // no OSDK
            console.log('[HANDLER] Wrote +0x10=1, +0x13=0, R8=0');
        } catch(e) {}
    },
    onLeave: function(retval) {
        console.log('[HANDLER] returned');
    }
});

// ============================================================
// Step 10: Periodically re-patch the port (DLL may overwrite)
// ============================================================
var portPatchInterval = setInterval(function() {
    try {
        var sdkPtr = addr(0x4b7c7a0).readPointer();
        if (!sdkPtr.isNull()) {
            var currentPort = sdkPtr.add(0x35c).readU16();
            if (currentPort !== ORIGIN_PORT) {
                sdkPtr.add(0x35c).writeU16(ORIGIN_PORT);
                console.log('[PORT-PATCH] Re-patched port from ' + currentPort + ' to ' + ORIGIN_PORT);
            }
        }
    } catch(e) {}
}, 1000);

console.log('=== Frida v59 Ready ===');
console.log('[INFO] Make sure origin-ipc-server.mjs is running on port ' + ORIGIN_PORT);
