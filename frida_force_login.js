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
            param2.add(0x13).writeU8(1);  // YES persona creation — triggers state transition
            console.log('[S2] *** Forced R8=0 + wrote +0x10=1, +0x13=1 ***');
            
            // Also try to change the state transition parameters
            // The handler calls: (*vtable+0x08)(sm, 1, 3)
            // We want to change (1,3) to something else
            // Hook the state transition function to change params
        } catch(e) {
            console.log('[S2] Write error: ' + e);
        }
    },
    onLeave: function(retval) {
        console.log('[S2] Handler returned — checking if state advanced...');
    }
});

// Strategy 3: NOP FUN_146e00f40 AND hook state transition to change (1,3) to (2,1)
try {
    var osdkLoader = addr(0x6e00f40);
    Memory.patchCode(osdkLoader, 4, function(code) {
        var w = new X86Writer(code, { pc: osdkLoader });
        w.putRet();
        w.flush();
    });
    console.log('[S3] Patched FUN_146e00f40 -> RET (OSDK screen NOP)');
} catch(e) {
    console.log('[S3] Could not patch FUN_146e00f40: ' + e);
}

// Hook the state transition function — log but DON'T change params
// (2,1) crashes. Let (1,3) happen — it advances the state machine.
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            var p2 = args[1].toInt32();
            var p3 = args[2].toInt32();
            console.log('[S3] State transition (' + p2 + ',' + p3 + ')');
        }
    });
    console.log('[S3] Hooked state transition at 0x146E126B0 (logging only)');
} catch(e) {
    console.log('[S3] Could not hook state transition: ' + e);
}

// Track PostAuth
Interceptor.attach(addr(0x6e213e0), {
    onEnter: function(args) {
        console.log('[S4] *** FUN_146e213e0 (PostAuth) CALLED! param1=' + args[0] + ' ***');
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
