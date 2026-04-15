/*
 * Frida v50: AGGRESSIVE — multiple strategies in one script.
 *
 * Strategy 1: Redirect CreateAccount→OriginLogin at wire level
 * Strategy 2: After response arrives, write Login data directly into
 *             the response object's fields (+0x10, +0x11, +0x12, +0x13)
 * Strategy 3: If handler still fails, call PostAuth directly
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v50: AGGRESSIVE Multi-Strategy ===');

// Strategy 1: Redirect CreateAccount→OriginLogin at send time
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

// Strategy 2: Intercept the CreateAccount handler — force success AND write response data
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var param1 = args[0]; // handler
        var param2 = args[1]; // response object
        var param3 = args[2]; // error code
        
        console.log('[S2] Handler called, param1=' + param1 + ' param2=' + param2 + ' R8=' + param3);
        
        // Force R8 = 0 (success path) — same as DLL's Patch 8 does for PreAuth
        this.context.r8 = ptr(0);
        
        // Write non-zero values into the response object
        try {
            param2.add(0x10).writeU8(1);  // UID non-zero
            param2.add(0x11).writeU8(0);
            param2.add(0x12).writeU8(0);
            param2.add(0x13).writeU8(0);  // NO persona creation
            console.log('[S2] *** Forced R8=0 + wrote +0x10=1, +0x13=0 ***');
        } catch(e) {
            console.log('[S2] Write error: ' + e);
        }
    },
    onLeave: function(retval) {
        console.log('[S2] Handler returned — checking if state advanced...');
    }
});

// Strategy 3: After the handler returns, check if we need PostAuth
// Hook FUN_146e213e0 (PostAuth setup) to see if it's called
Interceptor.attach(addr(0x6e213e0), {
    onEnter: function(args) {
        console.log('[S3] *** FUN_146e213e0 (PostAuth) CALLED! param1=' + args[0] + ' ***');
    }
});

// Track what happens after CreateAccount
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) { console.log('[FLOW] PreAuth handler'); }
});

// Track Logout
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 70) {
            console.log('[FLOW] Logout being sent');
        }
    }
});

// Track FetchClientConfig completion
var fccCount = 0;
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 9 && cmd === 1) {
            fccCount++;
            if (fccCount === 6) {
                console.log('[FLOW] All 6 FetchClientConfig sent');
            }
        }
    }
});

console.log('=== Frida v50 Ready ===');
console.log('S1: CreateAccount→OriginLogin redirect');
console.log('S2: Write response data directly into response object');
console.log('S3: Track PostAuth call');
