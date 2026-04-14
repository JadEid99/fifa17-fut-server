/*
 * Frida v26: Trace the state machine advance function (vtable+0x08)
 * to see what it does with state=3 and find the OSDK UI function to bypass.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v26: State Machine Trace ===');

// The CreateAccount cave calls: (*(*(param_1[1]) + 8))(param_1[1], 1, 3)
// param_1[1] is the Login state machine object with vtable 0x14389f938
// vtable+0x08 is the advance function
// Let's hook it to see what it does

// Hook the vtable+0x08 function for the Login state machine
// vtable at 0x14389f938, entry at +0x08 = 0x14389f940
// Read the function pointer from the vtable
var loginVtable = ptr('0x14389f938');
var advanceFnPtr = loginVtable.add(0x08).readPointer();
console.log('[INIT] Login vtable+0x08 -> ' + advanceFnPtr);

Interceptor.attach(advanceFnPtr, {
    onEnter: function(args) {
        var self = args[0];
        var success = args[1].toInt32();
        var nextState = args[2].toInt32();
        console.log('[STATE-ADVANCE] self=' + self + ' success=' + success + ' nextState=' + nextState);
        
        // Dump the state machine object
        try {
            var vtable = self.readPointer();
            console.log('[STATE-ADVANCE] vtable=' + vtable);
            // Read current state info
            console.log('[STATE-ADVANCE] +0x10=' + self.add(0x10).readU32());
            console.log('[STATE-ADVANCE] +0x14=' + self.add(0x14).readS64());
        } catch(e) {}
    }
});

// Also hook FUN_146e1c3f0 (Login type processor) to see if it ever gets called
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[LOGIN-PROC] FUN_146e1c3f0 CALLED! param1=' + args[0] + ' param2=' + args[1]);
    }
});

// Hook FUN_146e1e460 (post_PreAuth) to see when it fires
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[POST-PREAUTH] FUN_146e1e460 called');
    }
});

// Hook any function that might be the OSDK UI display
// The OSDK UI is likely triggered by a callback registered for state 3
// Let's trace calls in the 146e15xxx-146e16xxx range after the state advance
var callCount = 0;
[0x6e15320, 0x6e15bd0, 0x6e15eb0, 0x6e15fe0].forEach(function(off) {
    Interceptor.attach(addr(off), {
        onEnter: function(args) {
            console.log('[FN-' + off.toString(16) + '] called, arg0=' + args[0]);
        }
    });
});

console.log('=== Ready ===');
