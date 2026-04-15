/*
 * Frida v52: NUCLEAR OPTION — directly call PostAuth after PreAuth.
 * Skip CreateAccount and OSDK entirely.
 *
 * FUN_146e213e0 (PostAuth) is called 6 times during init with BlazeHub.
 * After PreAuth completes, call it again to set up the session.
 * Then send PostAuth RPC (comp=9, cmd=8) to the server.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v52: Direct PostAuth Call ===');

// Redirect CreateAccount→OriginLogin at send time
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[S1] Redirecting CreateAccount -> OriginLogin');
            this.context.r9 = ptr(0x98);
        }
    }
});

// After PreAuth handler returns, call PostAuth directly
var preAuthDone = false;
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) {
        this._param1 = args[0]; // PreAuth handler's param_1
        console.log('[PREAUTH] Handler called, param1=' + args[0]);
    },
    onLeave: function(retval) {
        if (preAuthDone) return;
        preAuthDone = true;
        console.log('[PREAUTH] Handler returned. Attempting direct PostAuth...');
        
        try {
            // Get BlazeHub from the PreAuth handler's param_1
            // From Frida v42: loginSM+0x08 = BlazeHub
            // loginSM = preAuthParam1 + 0x1DB0
            var preAuthParam1 = this._param1;
            var loginSM = preAuthParam1.add(0x1DB0);
            var blazeHub = loginSM.add(0x08).readPointer();
            console.log('[POSTAUTH-DIRECT] BlazeHub = ' + blazeHub);
            
            if (!blazeHub.isNull()) {
                // Call FUN_146e213e0(blazeHub, 0)
                var postAuthFn = new NativeFunction(addr(0x6e213e0), 'void', ['pointer', 'pointer']);
                console.log('[POSTAUTH-DIRECT] Calling FUN_146e213e0(blazeHub, 0)...');
                postAuthFn(blazeHub, ptr(0));
                console.log('[POSTAUTH-DIRECT] *** PostAuth returned! ***');
            } else {
                console.log('[POSTAUTH-DIRECT] BlazeHub is null');
            }
        } catch(e) {
            console.log('[POSTAUTH-DIRECT] Error: ' + e);
        }
    }
});

// Track all RPC sends
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            console.log('[RPC] comp=' + comp + ' cmd=' + cmd + ' (0x' + cmd.toString(16) + ')');
        }
    }
});

// Track PostAuth calls
Interceptor.attach(addr(0x6e213e0), {
    onEnter: function(args) {
        console.log('[POSTAUTH] FUN_146e213e0 called, param1=' + args[0]);
    }
});

// Track state transitions
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[TRANSITION] (' + args[1].toInt32() + ',' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

console.log('=== Frida v52 Ready ===');
