/*
 * Frida v63: Monitor Origin IPC + Blaze flow
 * No injections — just observe what happens with the correct Origin protocol
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v63: Origin Protocol Monitor ===');

// NOP OSDK screen
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
} catch(e) {}

// Monitor XML send
try {
    Interceptor.attach(addr(0x70e6ee0), {
        onEnter: function(args) {
            try { console.log('[XML-SEND] ' + args[1].readUtf8String()); } catch(e) {}
        }
    });
    console.log('[INIT] Hooked XML send');
} catch(e) {}

// Monitor Blaze RPCs
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            var names = {0x0A:'CreateAccount',0x28:'Login',0x32:'SilentLogin',0x46:'Logout',0x98:'OriginLogin',0x07:'PreAuth',0x08:'PostAuth',0x01:'FetchClientConfig',0x02:'Ping'};
            console.log('[RPC] comp=0x'+comp.toString(16)+' cmd='+(names[cmd]||'0x'+cmd.toString(16)));
        }
    }
});

// Monitor state transitions
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] transition(' + args[1].toInt32() + ', ' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

// Monitor login check
try {
    Interceptor.attach(addr(0x6e1dae0), {
        onEnter: function(args) {
            try {
                var arrStart = args[0].add(0x218).readPointer();
                var arrEnd = args[0].add(0x220).readPointer();
                var count = arrEnd.sub(arrStart).toInt32() / 0x20;
                console.log('[LOGIN-CHECK] array count=' + count);
            } catch(e) {}
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CHECK] returned ' + retval);
        }
    });
} catch(e) {}

// Monitor auth code request
try {
    Interceptor.attach(addr(0x70db3c0), {
        onEnter: function(args) {
            console.log('[AUTH-REQ] FUN_1470db3c0 called');
        }
    });
} catch(e) {}

// Monitor SendXml
try {
    Interceptor.attach(addr(0x70e67f0), {
        onEnter: function(args) {
            console.log('[SENDXML] called');
            try {
                if (!args[2].isNull()) console.log('[SENDXML] type="' + args[2].readUtf8String() + '"');
            } catch(e) {}
        },
        onLeave: function(retval) {
            console.log('[SENDXML] returned ' + retval);
        }
    });
} catch(e) {}

console.log('=== Frida v63 Ready ===');
