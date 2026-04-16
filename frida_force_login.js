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
// Step 4: Hook TCP connect + force reconnect to port 3216
// ============================================================
var sdkConnectAttempted = false;
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

// Force SDK reconnect after port is patched to 3216
// Poll until the port is 3216, then call the connect function
var reconnectInterval = setInterval(function() {
    if (sdkConnectAttempted) return;
    try {
        var sdkPtr = addr(0x4b7c7a0).readPointer();
        if (!sdkPtr.isNull()) {
            var port = sdkPtr.add(0x35c).readU16();
            if (port === 3216) {
                sdkConnectAttempted = true;
                clearInterval(reconnectInterval);
                console.log('[RECONNECT] Port is 3216 — forcing SDK reconnect...');
                
                // The SDK transport object is at sdkPtr + 0x168 area
                // FUN_14712ca40(transport+0x168, eventObj, signalObj, port)
                // But we need the right parameters. Simpler: just close the old socket
                // and let the SDK's message thread reconnect naturally.
                
                // Read the socket handle at transport+0x168+0x50
                // FUN_14712cc20 checks *(param_1+0x50) != -1
                // If we set it to -1, the SDK thinks it's disconnected and may reconnect
                
                // Find the transport objects
                var transports = [0x1b0, 0x258, 0x1b8, 0x178, 0x180, 0x168];
                for (var i = 0; i < transports.length; i++) {
                    try {
                        var tPtr = sdkPtr.add(transports[i]).readPointer();
                        if (!tPtr.isNull()) {
                            var sockHandle = tPtr.add(0x168 + 0x50).readS64();
                            if (sockHandle !== -1) {
                                console.log('[RECONNECT] Transport+0x' + transports[i].toString(16) + ' socket=' + sockHandle);
                                // Close the old socket to force reconnect
                                tPtr.add(0x168 + 0x50).writeS64(-1);
                                console.log('[RECONNECT] Set socket to -1 (disconnected)');
                            }
                        }
                    } catch(e) {}
                }
            }
        }
    } catch(e) {}
}, 500);

// ============================================================
// Step 5: Hook RequestAuthCode (FUN_1470db3c0) — BYPASS entirely
// Instead of letting it call SendXml (which fails), we provide
// the auth code directly by writing to the output params.
// FUN_1470db3c0(userId, requestObj, outAuthCode, outLength, param5)
// On success: *outAuthCode = string ptr, *outLength = length, return 0
// ============================================================
var fakeAuthPtr = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
try {
    Interceptor.attach(addr(0x70db3c0), {
        onEnter: function(args) {
            console.log('[AUTH-REQ] FUN_1470db3c0 called — BYPASSING with fake auth code');
            this._outAuth = args[2]; // R8 = pointer to auth code string pointer
            this._outLen = args[3];  // R9 = pointer to length
        },
        onLeave: function(retval) {
            // Write fake auth code to output params and return success
            try {
                if (this._outAuth && !this._outAuth.isNull()) {
                    this._outAuth.writePointer(fakeAuthPtr);
                    console.log('[AUTH-REQ] Wrote auth code ptr to R8 output');
                }
                if (this._outLen && !this._outLen.isNull()) {
                    this._outLen.writeS64(22);
                    console.log('[AUTH-REQ] Wrote length 22 to R9 output');
                }
                retval.replace(ptr(0)); // return 0 = success
                console.log('[AUTH-REQ] *** BYPASSED — returning fake auth code ***');
            } catch(e) {
                console.log('[AUTH-REQ] Bypass error: ' + e);
            }
        }
    });
    console.log('[INIT] Hooked RequestAuthCode with FULL BYPASS');
} catch(e) { console.log('[INIT] Auth hook error: ' + e); }

// ============================================================
// Step 6: Monitor SendXml (should not be called if bypass works)
// ============================================================
try {
    Interceptor.attach(addr(0x70e67f0), {
        onEnter: function(args) {
            console.log('[SENDXML] SendXml called (should not happen with bypass!)');
        }
    });
} catch(e) {}

// ============================================================
// Step 7: Track RPC sends + BLOCK CreateAccount + BLOCK Logout
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
            
            // BLOCK CreateAccount — it triggers the broken TDF decoder + Logout
            if (comp === 1 && cmd === 0x0A) {
                console.log('[RPC] *** BLOCKING CreateAccount → converting to Ping ***');
                this.context.r8 = ptr(0x9);
                this.context.r9 = ptr(0x2);
            }
            // BLOCK Logout — keep connection alive for queued Login job
            if (comp === 1 && cmd === 0x46) {
                console.log('[RPC] *** BLOCKING Logout → converting to Ping ***');
                this.context.r8 = ptr(0x9);
                this.context.r9 = ptr(0x2);
            }
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
