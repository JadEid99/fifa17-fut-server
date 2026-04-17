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

    // Step 1: resize array at +0x258
    try {
      console.log(ts() + "   step1: resize");
      var fn1 = new NativeFunction(addr(0x6e192f0), 'void', ['pointer', 'uint32']);
      fn1(param_1.add(0x258), 1);
      console.log(ts() + "   step1 OK");
    } catch(e) { console.log(ts() + "   step1 ERR: " + e); return ptr(0); }

    // Step 2: init tracking at +0x38
    try {
      console.log(ts() + "   step2: init");
      var fn2 = new NativeFunction(addr(0x6f8e7e0), 'void', ['pointer', 'uint32']);
      fn2(param_1.add(0x38), 1);
      console.log(ts() + "   step2 OK");
    } catch(e) { console.log(ts() + "   step2 ERR: " + e); return ptr(0); }

    // Step 3: set flags
    try {
      param_1.add(0x1a0).writeU16(0);
      param_1.add(0x210).writeU8(param_1.add(0x210).readU8() | 1);
      console.log(ts() + "   step3: flags OK");
    } catch(e) { console.log(ts() + "   step3 ERR: " + e); return ptr(0); }

    // Step 4: build entry + call LoginSender
    // IMPORTANT: Write entry to +0x218/+0x220 FIRST to prevent the DLL's
    // background LOGIN-INJECT from racing with us. The DLL checks
    // if (arrStart == 0 && arrEnd == 0) before injecting.
    try {
      var entry = Memory.alloc(0x40);
      var flagStr = Memory.allocUtf8String("1");
      entry.writePointer(flagStr);
      entry.add(0x10).writeU32(2);
      var config = entry.add(0x20);
      var authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
      config.add(0x10).writePointer(authToken);
      config.add(0x28).writeU16(0);
      entry.add(0x18).writePointer(config);

      // Block the DLL's LOGIN-INJECT by making the array look non-empty
      // Use a sentinel value (not our entry — the DLL might try to iterate it)
      param_1.add(0x218).writePointer(ptr(1));
      param_1.add(0x220).writePointer(ptr(1));

      console.log(ts() + "   step4: calling LoginSender");
      var fn3 = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
      var result = fn3(param_1, entry, config, 1);
      console.log(ts() + "   step4: LoginSender returned " + result);
      return ptr(1);
    } catch(e) { console.log(ts() + "   step4 ERR: " + e); return ptr(0); }

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
