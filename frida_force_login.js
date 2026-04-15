/*
 * Frida v58: ORIGIN IPC INTERCEPT
 *
 * Strategy: Instead of manipulating the game's internal state,
 * intercept the Origin SDK's XML communication and respond directly.
 *
 * The Origin SDK uses TCP sockets on localhost to talk to Origin.
 * We hook the XML send/receive functions to:
 * 1. Dump the XML the game sends (to understand the protocol)
 * 2. Intercept the auth code request and provide a fake response
 *
 * Key functions:
 * - FUN_1470e6ee0: Sends XML string to Origin via TCP
 * - FUN_1470e0f30: DispatchIncoming - receives and parses XML from Origin
 * - FUN_1470e67f0: RequestAuthCode wrapper (SendXml for auth)
 * - FUN_1470e1ed0: Send-and-wait (sends XML, waits for response with timeout)
 * - FUN_14712ca40: TCP connect to Origin (socket + connect)
 *
 * Also: DAT_144b7c7a0 = Origin SDK object pointer
 *        originSDK+0x35c = TCP port to connect to
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v58: Origin IPC Intercept ===');

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
// Step 2: Read Origin SDK state
// ============================================================
try {
    var sdkPtr = addr(0x4b7c7a0).readPointer();
    console.log('[SDK] DAT_144b7c7a0 (Origin SDK) = ' + sdkPtr);
    if (!sdkPtr.isNull()) {
        var port = sdkPtr.add(0x35c).readU16();
        console.log('[SDK] Origin TCP port (SDK+0x35c) = ' + port);
        // Read the SDK object's name/type
        try {
            var namePtr = sdkPtr.add(0x3b0).readPointer();
            if (!namePtr.isNull()) {
                var nameStr = namePtr.add(0x120).readPointer();
                console.log('[SDK] SDK+0x3b0+0x120 = ' + nameStr);
            }
        } catch(e) {}
    }
} catch(e) { console.log('[SDK] Read error: ' + e); }

// ============================================================
// Step 3: Hook XML send function (FUN_1470e6ee0)
// This is where the game sends XML to Origin via TCP
// ============================================================
try {
    Interceptor.attach(addr(0x70e6ee0), {
        onEnter: function(args) {
            try {
                var xmlStr = args[1].readUtf8String();
                console.log('[XML-SEND] === Outgoing XML ===');
                console.log(xmlStr);
                console.log('[XML-SEND] === End XML ===');
            } catch(e) {
                console.log('[XML-SEND] Could not read XML: ' + e);
            }
        }
    });
    console.log('[INIT] Hooked XML send (FUN_1470e6ee0)');
} catch(e) { console.log('[INIT] XML send hook error: ' + e); }

// ============================================================
// Step 4: Hook TCP connect (FUN_14712ca40)
// This is where the game connects to Origin's TCP port
// ============================================================
try {
    Interceptor.attach(addr(0x712ca40), {
        onEnter: function(args) {
            // param_4 is the port (u16)
            var port = args[3].toInt32() & 0xFFFF;
            console.log('[TCP] Connecting to Origin on port ' + port);
            this._port = port;
        },
        onLeave: function(retval) {
            console.log('[TCP] Connect result: ' + retval);
        }
    });
    console.log('[INIT] Hooked TCP connect');
} catch(e) { console.log('[INIT] TCP connect hook error: ' + e); }

// ============================================================
// Step 5: Hook FUN_1470db3c0 (RequestAuthCode) 
// This is the auth code provider that our DLL patches
// ============================================================
try {
    Interceptor.attach(addr(0x70db3c0), {
        onEnter: function(args) {
            console.log('[AUTH-REQ] FUN_1470db3c0 called (RequestAuthCode)');
            console.log('[AUTH-REQ] param1=' + args[0] + ' param2=' + args[1]);
            // Check if Origin SDK is available
            var sdkAvail = addr(0x4b7c7a0).readPointer();
            console.log('[AUTH-REQ] Origin SDK ptr = ' + sdkAvail);
        }
    });
    console.log('[INIT] Hooked RequestAuthCode');
} catch(e) { console.log('[INIT] Auth hook error: ' + e); }

// ============================================================
// Step 6: Hook FUN_1470e2840 (Origin SDK availability check)
// ============================================================
try {
    Interceptor.attach(addr(0x70e2840), {
        onEnter: function(args) {},
        onLeave: function(retval) {
            console.log('[SDK-CHECK] FUN_1470e2840 returned ' + retval + ' (Origin available: ' + (retval.toInt32() !== 0) + ')');
        }
    });
    console.log('[INIT] Hooked SDK availability check');
} catch(e) {}

// ============================================================
// Step 7: Hook the DispatchIncoming XML parser
// ============================================================
try {
    // FUN_1470e0f30 is the main dispatch loop
    Interceptor.attach(addr(0x70e0f30), {
        onEnter: function(args) {
            console.log('[XML-RECV] DispatchIncoming called');
        }
    });
    console.log('[INIT] Hooked DispatchIncoming');
} catch(e) { console.log('[INIT] Dispatch hook error: ' + e); }

// ============================================================
// Step 8: Hook FUN_1470e67f0 (SendXml for auth code)
// ============================================================
try {
    Interceptor.attach(addr(0x70e67f0), {
        onEnter: function(args) {
            console.log('[SENDXML] FUN_1470e67f0 called (auth SendXml)');
            try {
                var param3 = args[2]; // request type string
                var param4 = args[3]; // additional data
                if (!param3.isNull()) {
                    console.log('[SENDXML] param3 (type) = "' + param3.readUtf8String() + '"');
                }
                if (!param4.isNull()) {
                    try { console.log('[SENDXML] param4 = "' + param4.readUtf8String() + '"'); } catch(e) {}
                }
            } catch(e) { console.log('[SENDXML] read error: ' + e); }
        },
        onLeave: function(retval) {
            console.log('[SENDXML] returned ' + retval);
        }
    });
    console.log('[INIT] Hooked SendXml');
} catch(e) { console.log('[INIT] SendXml hook error: ' + e); }

// ============================================================
// Step 9: Track RPC sends (keep for reference)
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
// Step 10: Monitor state transitions
// ============================================================
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] transition(' + args[1].toInt32() + ', ' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

console.log('=== Frida v58 Ready ===');
