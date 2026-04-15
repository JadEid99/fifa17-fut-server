/*
 * Frida v49: Change BOTH the command AND the response vtable.
 *
 * The CreateAccount sender (FUN_146e15070) does:
 *   FUN_146dab760(puVar8, loginType, 10, ...);  // build RPC with cmd=10
 *   *puVar8 = &PTR_LAB_14389f2b8;               // set CreateAccountResponse vtable
 *
 * We need to change:
 *   cmd 10 → 0x98 (OriginLogin) at send time
 *   vtable 0x14389f2b8 → 0x1438aee60 (LoginResponse) in the RPC structure
 *
 * The Login sender (cmd=0x28) uses vtable 0x1438aee60 (LoginResponse).
 * LoginResponse has 5 fields and a different TDF decoder that might work.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v49: Full OriginLogin + LoginResponse Redirect ===');

var CA_VTABLE = addr(0x389f2b8);  // CreateAccountResponse
var LOGIN_VTABLE = addr(0x38aee60);  // LoginResponse

// Hook FUN_146df0e80 to change command at send time
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[RPC-SEND] Redirecting CreateAccount(10) -> OriginLogin(0x98)');
            this.context.r9 = ptr(0x98);
        }
    }
});

// Hook the CreateAccount sender function to change the response vtable
// FUN_146e15070 calls FUN_146dab760 then sets *puVar8 = CreateAccountResponse vtable
// We hook the function and after it returns, scan for the vtable and replace it
Interceptor.attach(addr(0x6e15070), {
    onEnter: function(args) {
        console.log('[CA-SENDER] FUN_146e15070 called');
    },
    onLeave: function(retval) {
        // The function returns param_2 which is the RPC descriptor
        // But the vtable was set on puVar8 which is inside the function
        // We can't easily access puVar8 from here
        // Instead, let's hook the response decoder and change the vtable there
        console.log('[CA-SENDER] returned');
    }
});

// Hook the RPC response decoder — when it creates the response object,
// change the vtable from CreateAccountResponse to LoginResponse
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        this._rpc = args[0];
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen === 148) {
                // This is likely the OriginLogin response (148 bytes = Login response)
                console.log('[RPC-RESP] 148-byte response — likely OriginLogin/Login response');
                this._isLoginResp = true;
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this._isLoginResp) {
            // After the decoder runs, scan the RPC structure for the CreateAccountResponse vtable
            // and replace it with LoginResponse vtable
            try {
                var rpc = this._rpc;
                // The response object is created during decode
                // Scan the RPC structure for the CA vtable
                for (var off = 0x60; off < 0x100; off += 8) {
                    try {
                        var val = rpc.add(off).readPointer();
                        if (val.equals(CA_VTABLE)) {
                            console.log('[RPC-RESP] Found CreateAccountResponse vtable at RPC+0x' + off.toString(16) + ', replacing with LoginResponse');
                            rpc.add(off).writePointer(LOGIN_VTABLE);
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }
    }
});

// Hook the handler to see the result
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            try {
                var resp = args[1];
                var vt = resp.readPointer();
                var b10 = resp.add(0x10).readU8();
                var b13 = resp.add(0x13).readU8();
                console.log('[HANDLER] vtable=' + vt + ' +0x10=' + b10 + ' +0x13=' + b13);
                if (vt.equals(LOGIN_VTABLE)) {
                    console.log('[HANDLER] *** LoginResponse vtable detected! ***');
                }
            } catch(e) {}
        }
    });
} catch(e) {}

// Track PreAuth
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[HANDLER] PreAuth'); }
    });
} catch(e) {}

console.log('=== Frida v49 Ready ===');
