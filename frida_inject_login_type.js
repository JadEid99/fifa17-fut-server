/*
 * FIFA 17 — Login Type Injection v15
 *
 * Replace LoginCheck (FUN_146e1dae0) to init arrays + call LoginSender.
 * Minimal hooks only — no hooks on functions called by LoginSender.
 */

"use strict";
var base = Process.getModuleByName("FIFA17.exe").base;
var t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }
function addr(off) { return base.add(off); }

console.log("=== FIFA 17 Login Type Injector v15 ===");

// NOP the OSDK screen loader
try {
  Memory.patchCode(addr(0x6e00f40), 4, function(code) {
    var w = new X86Writer(code, { pc: addr(0x6e00f40) });
    w.putRet();
    w.flush();
  });
  console.log(ts() + " Patched OSDK screen -> RET");
} catch(e) {}

// Exception handler
Process.setExceptionHandler(function(details) {
  console.log(ts() + " !!! CRASH: " + details.type + " at " + details.address);
  console.log(ts() + " !!! pc=" + details.context.pc);
  return false;
});

var loginTypeInjected = false;

// Replace FUN_146e1dae0 (LoginCheck)
try {
  Interceptor.replace(addr(0x6e1dae0), new NativeCallback(function(param_1) {
    if (loginTypeInjected) { return ptr(0); }
    loginTypeInjected = true;

    console.log(ts() + " LoginCheck REPLACED");

    var jobHandle;
    try { jobHandle = param_1.add(0x18).readPointer(); } catch(e) { console.log(ts() + " ERR read job: " + e); return ptr(0); }
    console.log(ts() + "   job=" + jobHandle);
    if (jobHandle.isNull()) { console.log(ts() + "   job NULL"); return ptr(0); }

    // Just return 1 to tell the game "login was initiated".
    // This prevents the Logout fallback path.
    // The DLL's background LOGIN-INJECT will handle the actual LoginSender call.
    // Even though the Login RPC doesn't dispatch on the wire, returning 1
    // changes the state machine behavior — the game won't send Logout immediately.
    
    // Block DLL's LOGIN-INJECT race
    param_1.add(0x218).writePointer(ptr(1));
    param_1.add(0x220).writePointer(ptr(1));
    
    console.log(ts() + "   returning 1 (login initiated)");
    return ptr(1);

  }, 'uint64', ['pointer']));
  console.log(ts() + " Replaced LoginCheck OK");
} catch(e) {
  console.log(ts() + " Replace FAILED: " + e.message);
}

// Minimal RPC monitor
Interceptor.attach(addr(0x6df0e80), {
  onEnter: function(args) {
    try {
      var comp = this.context.r8.toInt32() & 0xFFFF;
      var cmd = this.context.r9.toInt32() & 0xFFFF;
    } catch(e) { return; }
    if (comp === 1) {
      var names = {0xa:"CreateAccount", 0x28:"Login", 0x32:"SilentLogin", 0x46:"Logout", 0x98:"OriginLogin"};
      console.log(ts() + " AUTH RPC: " + (names[cmd] || "0x"+cmd.toString(16)));
    } else if (comp === 9 && (cmd === 7 || cmd === 8)) {
      console.log(ts() + " RPC: " + (cmd === 7 ? "PreAuth" : "PostAuth"));
    }
  }
});

// Monitor PreAuth handler
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) { console.log(ts() + " PreAuthHandler(err=" + args[2].toInt32() + ")"); },
  onLeave: function(ret) { console.log(ts() + " PreAuthHandler done"); }
});

// Monitor LoginTypesProcessor
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    console.log(ts() + " LoginTypesProcessor");
    try {
      var parent = args[0].add(0x08).readPointer();
      if (!parent.isNull()) {
        var flag = parent.add(0x53f).readU8();
        if (flag === 0) { parent.add(0x53f).writeU8(1); console.log(ts() + "   forced +0x53f=1"); }
      }
    } catch(e) {}
  },
  onLeave: function(ret) { console.log(ts() + " LoginTypesProcessor done"); }
});

// Monitor state transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM(" + args[1].toInt32() + "," + args[2].toInt32() + ")");
  }
});

console.log(ts() + " Ready.");
